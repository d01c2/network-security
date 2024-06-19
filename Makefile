all: tcp-block

tcp-block:
	go build -o tcp-block main.go

clean:
	go clean
	rm -f tcp-block