# agent-yard developer targets. `make test` is the one test command.
PY ?= python3
SHELL_SCRIPTS := host/bootstrap host/build-base-image host/render-nftables host/libexec/yard-quota selftest/probe.sh \
                 images/base/yard-git-credential bin/yard bin/yardd

.PHONY: test unit prove lint shellcheck tofu-validate boundaries e2e

test: unit

unit:
	$(PY) -m unittest discover -s tests/unit -t . -v

# The prover tests run inside `make test` when openshell-prover is on PATH
# (CI installs the pinned release); this target fails if it is missing.
prove:
	@command -v openshell-prover >/dev/null || { echo "openshell-prover not on PATH"; exit 1; }
	$(PY) -m unittest tests.unit.test_policy.ProverTests -v

shellcheck:
	shellcheck -x $(SHELL_SCRIPTS)

tofu-validate:
	cd infra && tofu init -backend=false -input=false >/dev/null && tofu validate

boundaries:
	$(PY) policies/boundaries/make_boundaries.py
	git diff --stat -- policies/boundaries

e2e:
	$(PY) tests/e2e/local_e2e.py
