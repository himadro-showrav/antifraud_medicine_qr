.PHONY: test
test:
	uv run --group dev pytest -v

.PHONY: lint
lint:
	uv run --group dev pre-commit run --all-files

.PHONY: run-api
run-api:
	uv run uvicorn antifraud_medicine_qr.api:app --reload

.PHONY: docker-build
docker-build:
	docker build --rm -t himadro-showrav/antifraud_medicine_qr .

.PHONY: docker-run
docker-run:
	docker run --rm -p 8000:8000 himadro-showrav/antifraud_medicine_qr
