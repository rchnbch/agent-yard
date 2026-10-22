"""Per-project dev images: resolve the Dockerfile, hash the context, build once.

Lookup order in the target repo: ``.openshell/Dockerfile``, then
``.devcontainer/Dockerfile``, else the shared base image. The build context
is the Dockerfile's directory. The tag is the SHA-256 of the context tree
plus the base image ID, so an unchanged project reuses its cached image and
a rebuilt base invalidates every project image.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tarfile
from dataclasses import dataclass
from typing import Callable, Sequence

DOCKERFILE_CANDIDATES = (".openshell/Dockerfile", ".devcontainer/Dockerfile")
BASE_LABEL = "org.agent-yard.base"
FORBIDDEN_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")
MAX_CONTEXT_BYTES = 512 * 1024**2


class ImageError(RuntimeError):
    pass


def find_dockerfile(repo_root: str) -> str | None:
    for rel in DOCKERFILE_CANDIDATES:
        path = os.path.join(repo_root, rel)
        if os.path.isfile(path) and not os.path.islink(path):
            return rel
    return None


def context_hash(context_dir: str, base_image_id: str) -> str:
    """Deterministic hash over relative paths, modes and contents."""
    h = hashlib.sha256()
    h.update(b"agent-yard-image-v1\0")
    h.update(base_image_id.encode() + b"\0")
    total = 0
    for root, dirs, files in os.walk(context_dir):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, context_dir)
            st = os.lstat(path)
            h.update(rel.encode() + b"\0")
            if stat.S_ISLNK(st.st_mode):
                h.update(b"L" + os.readlink(path).encode() + b"\0")
                continue
            h.update(oct(st.st_mode & 0o777).encode() + b"\0")
            total += st.st_size
            if total > MAX_CONTEXT_BYTES:
                raise ImageError(f"build context larger than {MAX_CONTEXT_BYTES} bytes")
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            h.update(b"\0")
    return h.hexdigest()


def safe_extract(tar_path: str, dest: str) -> str:
    """Extract a GitHub tarball, refusing links and paths that escape ``dest``.

    Returns the single top-level directory GitHub puts everything under.
    """
    with tarfile.open(tar_path) as tf:
        members = tf.getmembers()
        tops = {m.name.split("/", 1)[0] for m in members if m.name}
        if len(tops) != 1:
            raise ImageError("unexpected tarball layout")
        tf.extractall(dest, members=members, filter="data")
    return os.path.join(dest, tops.pop())


Run = Callable[[Sequence[str]], subprocess.CompletedProcess]


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), capture_output=True, text=True, check=False)


@dataclass
class Podman:
    """Container engine CLI. ``base_cmd`` is ["podman", "--url", URL] on the
    host (the rootless Podman user's API socket); ["docker"] works for the
    local Docker test setup."""

    base_cmd: list[str]
    run: Run = _run

    def _cmd(self, *args: str) -> list[str]:
        return [*self.base_cmd, *args]

    def workload_container(self, sandbox_name: str) -> str | None:
        p = self.run(self._cmd("ps", "-a", "--filter", f"label=openshell.ai/sandbox-name={sandbox_name}",
                               "--format", "{{.ID}} {{.Labels}}"))
        if p.returncode != 0:
            return None
        for line in p.stdout.splitlines():
            cid, _, labels = line.partition(" ")
            if "isolation-role=supervisor" not in labels and cid:
                return cid
        return None

    def copy_out(self, container: str, path: str, dest: str) -> bool:
        p = self.run(self._cmd("cp", f"{container}:{path}", dest))
        return p.returncode == 0

    def image_id(self, ref: str) -> str | None:
        p = self.run(self._cmd("image", "inspect", "--format", "{{.Id}}", ref))
        return p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else None

    def inspect(self, ref: str) -> dict:
        p = self.run(self._cmd("image", "inspect", ref))
        if p.returncode != 0:
            raise ImageError(f"podman image inspect {ref}: {p.stderr.strip()[:300]}")
        return json.loads(p.stdout)[0]

    def build(self, context_dir: str, dockerfile: str, tag: str) -> None:
        p = self.run(self._cmd("build", "--pull=never", "-f", dockerfile, "-t", tag, context_dir))
        if p.returncode != 0:
            raise ImageError(f"image build failed: {(p.stderr or p.stdout).strip()[-1500:]}")


def check_image(info: dict, base_id: str | None = None) -> None:
    """Reject images that would break auth or bypass the base image."""
    cfg = info.get("Config") or {}
    for kv in cfg.get("Env") or []:
        key = kv.split("=", 1)[0]
        if key in FORBIDDEN_ENV:
            raise ImageError(f"image sets {key}; it outranks or leaks the Claude token")
    labels = cfg.get("Labels") or info.get("Labels") or {}
    if BASE_LABEL not in labels:
        raise ImageError(f"image is not built FROM the agent-yard base image (no {BASE_LABEL} label)")
    user = (cfg.get("User") or "").split(":", 1)[0]
    if user in ("", "0", "root"):
        raise ImageError("image USER must be the non-root 'sandbox' user (uid 1000)")


def resolve_image(podman: Podman, base_image: str, repo_root: str | None, repo: str) -> dict:
    """Return {"image", "source", "hash"}; builds the project image if needed."""
    base_id = podman.image_id(base_image)
    if not base_id:
        raise ImageError(f"base image {base_image} is not present; run host/build-base-image")
    rel = find_dockerfile(repo_root) if repo_root else None
    if rel is None:
        check_image(podman.inspect(base_image))
        return {"image": base_image, "source": "base", "hash": base_id}
    context = os.path.dirname(os.path.join(repo_root, rel))
    digest = context_hash(context, base_id)
    slug = repo.lower().replace("/", "-").replace("_", "-").replace(".", "-")
    tag = f"localhost/agent-yard/dev-{slug}:{digest[:16]}"
    if not podman.image_id(tag):
        podman.build(context, os.path.join(repo_root, rel), tag)
    check_image(podman.inspect(tag), base_id)
    return {"image": tag, "source": rel, "hash": digest}
