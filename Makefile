.PHONY: sync format lint typecheck test audit check bicep helm container

UV := env UV_CACHE_DIR=/tmp/soffort-uv-cache .venv/bin/uv

sync:
	$(UV) sync --extra dev --frozen

format:
	$(UV) run ruff format .

lint:
	$(UV) run ruff format --check .
	$(UV) run ruff check .

typecheck:
	$(UV) run pyright

test:
	$(UV) run pytest

audit:
	$(UV) run pip-audit --strict

bicep:
	az bicep build --file infra/bootstrap.bicep --outfile /tmp/soffort-bootstrap.json
	az bicep build --file infra/main.bicep --outfile /tmp/soffort-main.json
	az bicep build --file infra/phase2-bootstrap.bicep --outfile /tmp/soffort-phase2.json
	$(UV) run python scripts/check-cost-guardrails.py /tmp/soffort-main.json

helm:
	helm lint deploy/charts/soffortbackend
	helm template soffortbackend deploy/charts/soffortbackend --namespace soffortbackend > /tmp/soffort-rendered.yaml
	$(UV) run python scripts/check-manifests.py /tmp/soffort-rendered.yaml

container:
	docker build --platform linux/arm64 -t soffortbackend:test .

check: lint typecheck test bicep helm
