build:
	@go build -o bin/Kodefx-server cmd/main.go

test:
	@go test -v./...

run:
	@./bin/Kodefx-server