GO      ?= go
BIN     ?= bin/mpinfra
PKG     := ./...
ADDR    ?= 127.0.0.1:8098
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

ifeq ($(OS),Windows_NT)
BIN := bin/mpinfra.exe
endif

.PHONY: all build test vet check serve dist fmt tidy clean

all: build

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/mpinfra

test:
	$(GO) test $(PKG)

vet:
	$(GO) vet $(PKG)

check: vet test

serve: build
	$(BIN) serve -config config.example.yaml -addr $(ADDR) -insecure-bind

dist:
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o dist/mpinfra-linux-amd64 ./cmd/mpinfra
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o dist/mpinfra-windows-amd64.exe ./cmd/mpinfra
	cd dist && sha256sum mpinfra-* > SHA256SUMS

fmt:
	$(GO) fmt $(PKG)

tidy:
	$(GO) mod tidy

clean:
	rm -r bin dist
