# suricata-rule
This is the assignment repository for the **System Network Security** course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
Create a snort (suricata) rule file to detect specific site traffic.

## Instructions
```
suricata -s test.rules -i eth0
```

## Details
- Create a rule in the `test.rules` file to detect 20 sites.
- Then check `fast.log` to verify that the 20 sites are detected correctly (all sids in the rules file should be logged in the `fast.log` file).
- Implement detection for sites with TLS communication (HTTPS) as well as sites with plain text communication (HTTP).

## Additional
You should also upload the project file(Makefile) along with source code files.