# netfilter-test
This is the assignment repository for the **System Network Security** course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
Use netfilter to block harmful sites.

## Instructions
```
make
sudo ./netfilter-test test.gilgil.net
```

## Details
- Use the `iptables` command to jump all packets sent and received into the netfilter queue.
- It targets sites that communicate in plain text (but not HTTPS). Extract the Host field from the HTTP request and determine if the Host value is the same as the argument.
- If it is determined to be a harmful site, change the third argument of the nfq_set_verdict function from NF_ACCEPT to NF_DROP and call the function to see if the traffic is blocked.

## Additional
You should also upload the project file(Makefile) along with source code files.