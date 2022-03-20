dependence:
	go mod tidy
	go mod vendor

test: dependence
	go test -cover -race ./...

.PHONY:	dependence