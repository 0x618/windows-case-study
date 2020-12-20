# Windows Case Study

I wrote this program in order to familiarize myself with some of the components of Windows which are not well documented by Microsoft, as well as to learn how to write my own shellcode.  This code is not malicious, but it behaves very similarly to malware, in that it makes a call to a WinAPI function using x86 assembly.  This assembly code is contained within a C program mostly for ease of printing, but also to illustrate the difference between making a WinAPI function call in assembly and making the same function call in C using the windows.h library (the "standard" way of doing it).  

***Note:  This program was written for and tested on Windows 7 SP1 (6.1.7601).***

This project was broken up into three parts:
1. Find the base address of Kernel32.dll in memory
2. Locate the IMAGE_EXPORT_DIRECTORY structure within Kernel32 and get information about the export table of Kernel32
3. Find a given Kernel32 function by name within the export table and call the function
