all: pcap-test

pcap-test:
	go build -o pcap-test main.go

clean:
	go clean
	rm -f pcap-test 