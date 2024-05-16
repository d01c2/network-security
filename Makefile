all: 1m-block

netfilter-test:
	go build -o 1m-block main.go

clean:
	go clean
	rm -f 1m-block