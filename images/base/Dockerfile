# agent-yard base image: what every job's dev image builds FROM.
# Debian + the unmodified Claude Code native binary + git, gh, curl, jq and
# common build tools. Project images (.openshell/Dockerfile in the target
# repo) must start with `FROM localhost/agent-yard/base:latest`; yard checks
# the org.agent-yard.base label to enforce that.
#
# Never set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN here: both outrank
# CLAUDE_CODE_OAUTH_TOKEN, which yard injects at sandbox start.

ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
FROM ${DEBIAN_IMAGE}

ARG CLAUDE_CODE_VERSION=2.1.308
ARG TARGETARCH=amd64

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git gh jq less procps openssh-client unzip xz-utils zstd \
      build-essential pkg-config python3 python3-venv python3-pip \
 && rm -rf /var/lib/apt/lists/*

# Claude Code: fetch the release manifest, then the binary, and verify its
# SHA-256 against the manifest before installing it as a real file (OpenShell
# matches the executable's real path, so no symlinks). An optional build
# secret `extra_ca` adds a CA for TLS-intercepting proxies; verification is
# never disabled.
RUN --mount=type=secret,id=extra_ca,required=false set -eu; \
    if [ -s /run/secrets/extra_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca > /tmp/ca.pem; \
      export CURL_CA_BUNDLE=/tmp/ca.pem; fi; \
    case "$TARGETARCH" in amd64) plat=linux-x64 ;; arm64) plat=linux-arm64 ;; *) echo "unsupported arch $TARGETARCH"; exit 1 ;; esac; \
    base=https://downloads.claude.ai/claude-code-releases/$CLAUDE_CODE_VERSION; \
    curl -fsSL "$base/manifest.json" -o /tmp/manifest.json; \
    want=$(jq -r --arg p "$plat" '.platforms[$p].checksum' /tmp/manifest.json); \
    echo "$want" | grep -Eq '^[a-f0-9]{64}$'; \
    curl -fsSL "$base/$plat/claude" -o /usr/local/bin/claude; \
    echo "$want  /usr/local/bin/claude" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/claude; \
    rm -f /tmp/manifest.json /tmp/ca.pem; \
    /usr/local/bin/claude --version

COPY yard-git-credential /usr/local/bin/yard-git-credential
COPY gitconfig /etc/gitconfig
RUN chmod 0755 /usr/local/bin/yard-git-credential \
 && useradd --uid 1000 --user-group --home-dir /sandbox --create-home --shell /bin/bash sandbox

# Headless, no self-updates, no telemetry or error reporting from the CLI.
ENV DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    GH_PROMPT_DISABLED=1 \
    GIT_TERMINAL_PROMPT=0

LABEL org.agent-yard.base="1" \
      org.opencontainers.image.source="https://github.com/rchnbch/agent-yard"

USER sandbox
WORKDIR /sandbox
