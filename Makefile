.PHONY: all clean build buildgeth test lint fill

all: clean build

build:
	go build .

buildgeth:
	go build github.com/ethereum/go-ethereum/cmd/geth

clean:
	rm -rf rpctestgen tests

test:
	go test ./...

lint:
	golangci-lint run --config .golangci.yml ./...

fill: build buildgeth
	./rpctestgen --bin ./geth -chain ./chain
