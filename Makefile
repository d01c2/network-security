all: echo-client

echo-client:
	go build -o echo-client main.go

clean:
	go clean
	rm -f echo-client