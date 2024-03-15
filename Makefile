all: add-nbo

add-nbo: 
	go build -o add-nbo main.go

clean:
	go clean
	rm -f add-nbo