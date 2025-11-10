# Makefile for nlsn-monitor

.PHONY: build test clean install lint run help

# Variables
BINARY_NAME=nlsn-monitor
INSTALL_PATH=/usr/local/bin
GO=go
GOFLAGS=-v

# Build binary
build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) ./cmd/nlsn-monitor

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-linux-amd64 ./cmd/nlsn-monitor
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BINARY_NAME)-darwin-amd64 ./cmd/nlsn-monitor
	GOOS=darwin GOARCH=arm64 $(GO) build -o $(BINARY_NAME)-darwin-arm64 ./cmd/nlsn-monitor

# Run tests
test:
	$(GO) test -v -race -coverprofile=coverage.out ./...

# Test coverage
coverage: test
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Install binary
install: build
	sudo install -m 755 $(BINARY_NAME) $(INSTALL_PATH)
	sudo setcap cap_net_raw=eip $(INSTALL_PATH)/$(BINARY_NAME) || echo "Warning: Could not set capabilities."

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*
	rm -f coverage.out coverage.html

# Lint code
lint:
	golangci-lint run ./... || echo "golangci-lint not installed"

# Format code
fmt:
	$(GO) fmt ./...

# Run directly
run: build
	@echo "Note: Requires sudo for packet capture"
	sudo ./$(BINARY_NAME) start

# Initialize configuration
init-config:
	@mkdir -p ~/.config/nlsn-pcap
	@if [ ! -f ~/.config/nlsn-pcap/config.yaml ]; then \
		cp configs/config.example.yaml ~/.config/nlsn-pcap/config.yaml; \
		echo "Created config: ~/.config/nlsn-pcap/config.yaml"; \
	else \
		echo "Config already exists"; \
	fi

# Help
help:
	@echo "Available targets:"
	@echo "  build       - Build binary"
	@echo "  test        - Run tests"
	@echo "  install     - Install binary"
	@echo "  run         - Build and run (requires sudo)"
	@echo "  init-config - Create default config"
	@echo "  help        - Show this help"
