#Makefile
all: sum-test

sum-test:
	go build -o sum-test sum.go main.go

clean:
	go clean
	rm -f sum-test