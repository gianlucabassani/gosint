.PHONY: build check fmt vet test clean install run

BINARY := gosint
CMD     := ./cmd

# Default: build the binary.
build:
	go build -o $(BINARY) $(CMD)

# check — the gate to run before considering a change done (see AGENT.md).
check: fmt vet build test
	@echo "✓ check passed"

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./...

install:
	go install $(CMD)

clean:
	rm -f $(BINARY)
