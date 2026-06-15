.PHONY: build build-capture test lint fmt fmt-check up up-capture down logs shell-rust clean

COMPOSE := docker compose -f deploy/docker-compose/compose.yaml
COMPOSE_CAPTURE := docker compose -f deploy/docker-compose/compose.capture.yaml
RUST_IMAGE := rust:1.88-bookworm

build:
	docker build -f docker/Dockerfile.rust -t netwatcher-rust:local .

build-capture:
	docker build -f docker/capture/Dockerfile -t netwatcher-capture:local .

test:
	docker run --rm -v "$(CURDIR):/workspace" -w /workspace $(RUST_IMAGE) \
		bash -c 'apt-get update -qq && apt-get install -y -qq cmake libssl-dev pkg-config >/dev/null && cargo test --workspace'

lint:
	docker run --rm -v "$(CURDIR):/workspace" -w /workspace $(RUST_IMAGE) \
		bash -c 'apt-get update -qq && apt-get install -y -qq cmake libssl-dev pkg-config >/dev/null && rustup component add rustfmt clippy >/dev/null && cargo fmt --check && cargo clippy --workspace -- -D warnings'

coverage:
	docker run --rm -v "$(CURDIR):/workspace" -w /workspace $(RUST_IMAGE) \
		bash -c 'apt-get update -qq && apt-get install -y -qq cmake libssl-dev pkg-config >/dev/null && cargo install cargo-tarpaulin --locked >/dev/null 2>&1 && cargo tarpaulin -p netwatcher-common -p netwatcher-enricher -p netwatcher-shipper -p netwatcher-gateway -p netwatcher-mcp --fail-under 80 --out Stdout'

fmt:
	docker run --rm -v "$(CURDIR):/workspace" -w /workspace $(RUST_IMAGE) cargo fmt --all

fmt-check: lint

up: build
	$(COMPOSE) up -d --build

up-capture: build-capture
	$(COMPOSE) --profile capture up -d capture-agent

down:
	$(COMPOSE) --profile capture down

logs:
	$(COMPOSE) logs -f gateway indexer enricher

shell-rust:
	docker run --rm -it -v "$(CURDIR):/workspace" -w /workspace $(RUST_IMAGE) bash

clean:
	rm -rf target/

k8s-apply:
	kubectl apply -k deploy/kubernetes/

k8s-delete:
	kubectl delete -k deploy/kubernetes/ --ignore-not-found
