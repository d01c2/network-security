# 1m-block
This is the assignment repository for the **System Network Security** course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
Block 1 million harmful sites.

## Instructions
```
make
sudo ./1m-block top-1m.txt
```

## Details
- Perform this assignment after performing the previous assignment (netfilter-test).
- Implement logic that considers 1 million sites in a zip file to be harmful and determines if they are in the list of 1 million by looking at the Host value after "Host: " in the HTTP request.
- For the list of 1 million sites (762564 to be exact), see the following file https://gitlab.com/gilgil/top-1m
- The implementation of the logic should focus on memory and search speed (it shouldn't slow down your program so much that you can't actually surf the internet with it running. There are several ways to do this, the easiest being a sequential search, but this will slow down the search because the logic is comparing a million things sequentially. Whatever method you use, try to improve speed and consider different ways to reduce memory usage if possible).
- Measure how long it takes to load a million into memory (time diffing) and how much memory it takes up (using the top command). Also time the portion of the million that searches for a specific host (time diffing).
- Testing with a web browser is difficult because most sites use HTTPS communication by default these days, so you'll need to generate HTTP traffic with the wget command.
- You can modify the top-1m file format to suit your own program.

## Additional
You should also upload the project file(Makefile) along with source code files.