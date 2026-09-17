GO ?= go
BIN := bin
export DATABASE_URL ?= postgres://iorec:iorec@127.0.0.1:54329/iorec
export TEST_DATABASE_URL ?= postgres://iorec:iorec@127.0.0.1:54329/iorec_test
export OBJECT_STORE_DIR ?= ./data/objects
export IOREC_BOOTSTRAP_PROJECT_TOKEN ?= iorp_devtoken0000000000000000

.PHONY: build test vet run-api run-worker fake web-build web-dev db-up db-down images compose-up lint

build:
	$(GO) build -o $(BIN)/platform-api ./cmd/platform-api
	$(GO) build -o $(BIN)/pipeline-worker ./cmd/pipeline-worker
	$(GO) build -o $(BIN)/fake-collector ./cmd/fake-collector

vet:
	$(GO) vet ./...

test: vet
	$(GO) test ./... -count=1

db-up:
	docker run -d --name iorec-pg -e POSTGRES_USER=iorec -e POSTGRES_PASSWORD=iorec -e POSTGRES_DB=iorec -p 127.0.0.1:54329:5432 postgres:17.11-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73 -c fsync=off || docker start iorec-pg
	@until docker exec iorec-pg pg_isready -U iorec >/dev/null 2>&1; do sleep 1; done
	-docker exec iorec-pg psql -U iorec -c 'create database iorec_test'

db-down:
	-docker rm -f iorec-pg

run-api: build
	IOREC_AUTH_MODE=dev IOREC_API_ADDR=127.0.0.1:8080 $(BIN)/platform-api

run-worker: build
	$(BIN)/pipeline-worker

fake: build
	$(BIN)/fake-collector --token $(IOREC_BOOTSTRAP_PROJECT_TOKEN) --drop-batch 2 --corrupt-hash 4 --conflict 5

web-build:
	cd web && npm ci --no-audit --no-fund && npm run build

web-dev:
	cd web && npm run dev

images:
	docker build -f deploy/Dockerfile.api -t iorec/platform-api:0.1 .
	docker build -f deploy/Dockerfile.worker -t iorec/pipeline-worker:0.1 .
	docker build -f deploy/Dockerfile.web -t iorec/web-console:0.1 .

compose-up:
	docker compose -f deploy/compose.yaml -f deploy/compose.dev.yaml up -d --build
