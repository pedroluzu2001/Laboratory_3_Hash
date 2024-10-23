# Lab 3: Hashing
**Objective:** The key objective of this lab is to understand the range of hashing methods used, analyse the strength of each of the methods, and in the usage of salting. Overall the most popular hashing methods are: MD5 (128-bit); SHA-1 (160-bit); SHA-256 (256-bit); SHA-3 (256-bit), bcrypt (192-bit) and PBKDF2 (256-bit). The methods of bcrypt, scrypt and PBKDF2 use a number of rounds, and which significantly reduce the hashing rate. This makes the hashing processes much slower, and thus makes the cracking of hashed passwords more difficult. We will also investigate the key hash cracking tools such as hashcat and John The Ripper.

## A._Hashinng
___________________________________________________________________________________________________________________________________________________________________________________

In this section we will look at some fundamental hashing methods.

# Hash Matching Exercise

| No  | Description | Result |
| --- | ----------- | ------ |
| A.1 | Using (either on your Windows desktop or on Ubuntu): <br> Web link (Hashing): <br> [MD5 Hash](http://asecuritysite.com/encryption/md5) <br> Match the hash signatures with their words ("Falkirk", "Edinburgh", "Glasgow" and "Stirling"). <br> ```03CF54D8CE19777B12732B8C50B3B66F <br> D586293D554981ED611AB7B01316D2D5 <br> 48E935332AADEC763F2C82CDB4601A25 <br> EE19033300A54DF2FA41DB9881B4B723 ``` | 03CF5: Is it<br> [Falkirk] [Edinburgh] [Glasgow] [Stirling]? <br> D5862: Is it<br> [Falkirk] [Edinburgh] [Glasgow] [Stirling]? <br> 48E93: Is it<br> [Falkirk] [Edinburgh] [Glasgow] [Stirling]? <br> EE190: Is it<br> [Falkirk] [Edinburgh] [Glasgow] [Stirling]? |
| A.2 | Repeat Part 1, but now use openssl, such as: <br> `echo -n 'Falkirk' \| openssl md5` | 03CF5: Is it <br>[Falkirk] [Edinburgh] [Glasgow] [Stirling]? <br> D5862: Is it<br> [Falkirk] [Edinburgh] [Glasgow] [Stirling]? <br> 48E93: Is it<br> [Falkirk] [Edinburgh] [Glasgow] [Stirling]? <br> EE190: Is it<br> [Falkirk] [Edinburgh] [Glasgow] [Stirling]? |





