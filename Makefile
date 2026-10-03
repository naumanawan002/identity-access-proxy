.PHONY: all build test clean run-proxy run-upstream-admin run-upstream-billing mint-token docker-up docker-down

BIN_DIR := ./bin

all: build test

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/proxy ./cmd/proxy
	go build -o $(BIN_DIR)/token-dispenser ./cmd/token-dispenser
	go build -o $(BIN_DIR)/upstream ./examples/upstream
	@echo "Build complete. Artifacts written to $(BIN_DIR)/"

test:
	go test -v -race ./...

clean:
	rm -rf $(BIN_DIR)

run-proxy:
	go run ./cmd/proxy -config examples/config.json

run-upstream-admin:
	go run ./examples/upstream -port 8081 -name "admin-service"

run-upstream-billing:
	go run ./examples/upstream -port 8082 -name "billing-service"

mint-token:
	go run ./cmd/token-dispenser -sub alice -email alice@example.com -roles admin -trust high

docker-up:
	docker compose up --build

docker-down:
	docker compose down
