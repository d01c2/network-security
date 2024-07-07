# add-nbo
This is the assignment repository for the **System Network Security** course held at Korea University in Spring 2024. Below are the requirements for the assignment:

## Assignment
A 32-bit number is stored in files with a size of 4 bytes(in network byte order). Write a program that reads numbers from two files and prints their sum.

## Instructions
```
make
./add-nbo thousand.bin five-hundred.bin
```

## Details
- Use `uint32` to handle 4-byte integers.
- Ignore overflow in integer addition.
- Implement error handling for cases where files fail to open properly or when the file size is less than 4 bytes.

## Additional
You should also upload the project file(Makefile) along with source code files.
