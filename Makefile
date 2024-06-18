all: echo-server

echo-server:
	go build -o echo-server main.go

clean:
	go clean
	rm -f echo-server