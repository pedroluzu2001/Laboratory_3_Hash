# Lab 3: Hashing
**Objective:** The key objective of this lab is to understand the range of hashing methods used, analyse the strength of each of the methods, and in the usage of salting. Overall the most popular hashing methods are: MD5 (128-bit); SHA-1 (160-bit); SHA-256 (256-bit); SHA-3 (256-bit), bcrypt (192-bit) and PBKDF2 (256-bit). The methods of bcrypt, scrypt and PBKDF2 use a number of rounds, and which significantly reduce the hashing rate. This makes the hashing processes much slower, and thus makes the cracking of hashed passwords more difficult. We will also investigate the key hash cracking tools such as hashcat and John The Ripper.

## A._Hashinng
___________________________________________________________________________________________________________________________________________________________________________________

In this section we will look at some fundamental hashing methods.

# Hash Matching Exercise

| No  | Description | Result |
| --- | ----------- | ------ |
| A.1 | Using (either on your Windows desktop or on Ubuntu): <br> Web link (Hashing): <br> [MD5 Hash](http://asecuritysite.com/encryption/md5) <br> Match the hash signatures with their words ("Falkirk", "Edinburgh", "Glasgow" and "Stirling"). <br> ```03CF54D8CE19777B12732B8C50B3B66F <br> D586293D554981ED611AB7B01316D2D5 <br> 48E935332AADEC763F2C82CDB4601A25 <br> EE19033300A54DF2FA41DB9881B4B723 ``` | 03CF5: Is it<br>  `Edinburgh` <br> D5862: Is it<br> `Glasgow`<br> 48E93: Is it<br> `Falkirk` <br> EE190: Is it<br>  `Stirling` |
| A.2 | Repeat Part 1, but now use openssl, such as: <br> `echo -n 'Falkirk' \| openssl md5` | 03CF5: Is it <br>`Edinburgh`<br> D5862: Is it<br>`Glasgow` <br> 48E93: Is it<br> `Falkirk` <br> EE190: Is it<br> `Stirling` |
| A.3 | Using: <br> Web link (Hashing): <br> [MD5 Hash](http://asecuritysite.com/encryption/md5) <br> Determine the number of hex characters for the hash signatures defined. Note: perhaps copy and paste your hash to an online character counter? | MD5 hex chars: <br> SHA-1 hex chars: <br> SHA-256 hex chars: <br> SHA-384 hex chars: <br> SHA-512 hex chars: <br> How does the number of hex characters relate to the length of the hash signature? |
| A.4 | For the following /etc/shadow file, determine the matching password: <br> bi11: \$apr1\$wazs/8Tm\$jDZmizBct/c2hysERcZ3m1 <br> mike: \$apr1\$mKfrJqUI\$Kx0CL9krmqhCu0SHKqp5Q0 <br> fred: \$apr1\$Jbe/hcIb\$/k3A4kjpJyC06BUUaPRKS0 <br> ian: \$apr1\$0GyPhsLi\$jTTzW0HNS4C15ZEoyFLjB. <br> jane: \$1\$rqOIRBBN\$R2pOQH9egTTVN1N1st2u7. <br> [Hint: `openssl passwd -aprl -salt ZaZS/8TF napier`] | The passwords are password, napier, inkwell, and Ankle123. <br> Bill's password: <br> Mike's password: <br> Fred's password: <br> Ian's password: <br> Jane's password: |
| A.5 | From Ubuntu, download the following: <br> Web link (Files): <br> [Files.zip](http://asecuritysite.com/files02.zip) <br> (a quick way to download is `wget asecuritysite.com/files02.zip`) and the files should have the following MD5 signatures: <br> MD5 (1.txt) = `5d41402abc4b2a76b9719d911017c592` <br> MD5 (2.txt) = `69faab6268350295550de7d587bc323d` <br> MD5 (3.txt) = `fea0f1f6fede90bd0a925b4194deac11` <br> MD5 (4.txt) = `d89b56f81cd7b82856231e662429bcf2` | Which file(s) have been modified? |
| A.6 | From Ubuntu, download the following ZIP file: <br> Web link (PS Files): <br> [Letters.zip](http://asecuritysite.com/letters.zip) <br> (a quick way to download is `wget asecuritysite.com/letters.zip`) <br> On your Ubuntu instance, you should be able to view the files by double-clicking on them in the file explorer (as you should have a PostScript viewer installed). <br> `cat letter_of_rec.ps openssl md5` | Do the files have different contents? <br> Now determine the MD5 signature for them. What can you observe from the result? |


## B Hash Cracking (Hashcat)

| No   | Description | Result |
|------|-------------|--------|
| B.1 | Run the hashcat benchmark (e.g., `hashcat -b -m 0`), and complete the following: | Hash rate for MD5: <br> Hash rate for SHA-1: <br> Hash rate for SHA-256: <br> Hash rate for APR1: |
| B.2 | On Ubuntu, create a word file (`words`) with the words "napier", "password", "Ankle123", and "inkwell". <br> Using hashcat, crack the following MD5 signatures (`hash1`): <br> `232DD5D7274E0D662F36C575A3BD634C` <br> `5F4DCC3B5AA765D61D8327DEB882CF99` <br> `6D5875265D1979BDAD1C8A8F383C5FF5` <br> `04013F78ACCFEC9B673005FC6F20698D` <br> Command used: `hashcat -m 0 hash1 words` | 232DD...634C: <br> Is it `[napier][password][Ankle123][inkwell]`? <br> 5F4DC...CF99: <br> Is it `[napier][password][Ankle123][inkwell]`? <br> 6D587...5FF5: <br> Is it `[napier][password][Ankle123][inkwell]`? <br> 04013...698D: <br> Is it `[napier][password][Ankle123][inkwell]`? |
| B.3 | Using the method from the first part of this tutorial, find the following for names of fruits (all lowercase): <br> `FE01D67A002DFA0F3AC084298142ECCD` <br> `1F3870BE274F6C49B3E31A0C6728957F` <br> `72B302BF297A228A75730123EFEF7C41` <br> `8893DC16B1B2534BAB7B03727145A2BB` <br> `889560D93572D538078CE1578567B91A` | FE01D: <br> 1F387: <br> 72B30: <br> 8893D: <br> 88956: |
| B.4 | Put this SHA-256 value in a file named `file.txt`: <br> `106a5842fc5fce6f663176285ed1516dbb1e3d15c05abab12fdca46d60b539b7` <br> By adding a word "help" in a word file `words.txt`, prove that the following cracks the hash (where `file.txt` contains the hashed value): <br> `hashcat -m 1400 file.txt words.txt` | |
| B.5 | The following is an NTLM hash for "help": <br> `0333c27eb4b9401d91fef02a9f74840e` <br> Prove that the following can crack the hash (where `file.txt` contains the hashed value): <br> `hashcat -m 1000 file.txt words.txt` | |

The cracked hashed are stored in:

`~/.hashcat/hashcat.potfile`

What do you observe when you use the command:

`cat ~/.hashcat/hashcat.potfile`

Note, hashcat doesn’t show previously cracked values, so if you want it to recrack them, just 
use:

`rm ~/.hashcat/hashcat.potfile`

### B.6 Now crack the following Scottish football teams (all are single words):
```
635450503029fc2484f1d7eb80da8e25bdc1770e1dd14710c592c8929ba37ee9
BEF68628460A29657F55A2860407969E3AF183E889021B30091C815F6C6B248D
bc5fb9abe8d5e72eb49cf00b3dbd173cbf914835281fadd674d5a2b680e47d50
6ac16a68ac94ca8298c9c2329593a4a4130b6fed2472a98424b7b4019ef1d968
```
```
Football teams:

```
### B.7 Rather than use a dictionary, we can use a brute force a hashed password using a 
lowercase character set:

`hashcat -a 3 -m 1400 file.txt ?l?l?l?l?l?l?l?l --increment`

Using this style of command (look at the hash type and perhaps this is a SHA-256 hash), 
crack the following words:

```
4dc2159bba05da394c3b94c6f54354db1f1f43b321ac4bbdfc2f658237858c70
0282d9b79f42c74c1550b20ff2dd16aafc3fe5d8ae9a00b2f66996d0ae882775
47c215b5f70eb9c9b4bcb2c027007d6cf38a899f40d1d1da6922e49308b15b69
```
```
Words:
Number of tests for each sequence tried:

a->z:
aa->zz:
aaa->zzz:
aaaa->zzzz:

What happens when you take the “--increment” flag away?
```

### B.8 We can focus on given letters, such as where we add a letter or a digit at the end:
 ```
hashcat -a 3 -m 1000 file.txt password?l
hashcat -a 3 -m 1000 file.txt password?u
hashcat -a 3 -m 1000 file.txt password?d

```

Using these commands, crack the following:

```
7a6c8de8ad7f89b922cc29c9505f58c3
db0edd04aaac4506f7edab03ac855d56
```
Note: Remember to try both MD5 (0) and NTLM hash (1000).

```
Words:

Number of tests for each:
```

## C  Hashing Cracking (John The Ripper)

All of the passwords in this section are in lowercase.


| No   | Description | Result |
|------|-------------|--------|
| C.1 | On Ubuntu, and using John the Ripper with a word list containing fruit names, crack the following `pwdump` passwords: <br> `fred:500:E79E56A8E5C6F8FEAAD3B435B51404EE:5EBE7DFA074DA8EE8AEF1FAA2BBDE876:::` <br> `bert:501:10EAF413723CBB15AAD3B435B51404EE:CA8E025E9893E8CE3D2CBF847FC56814:::` | Fred: <br> Bert: |
| C.2 | On Ubuntu, and using John the Ripper, crack the following `pwdump` passwords (they are names of major Scottish cities/towns): <br> `Admin:500:629E2BA1C0338CE0AAD3B435B51404EE:9408CB400B20ABA3DFEC054D2B6EE5A1:::` <br> `fred:501:33E58ABB4D723E5EE72C57EF50F76A05:4DFC4E7AA65D71FD4E06D061871C05F2:::` <br> `bert:502:BC2B6A869601E4D9AAD3B435B51404EE:2D8947D98F0B09A88DC9FCD6E546A711:::` | Admin: <br> Fred: <br> Bert: |
| C.3 | On Ubuntu, and using John the Ripper, crack the following `pwdump` passwords (they are the names of animals): <br> `fred:500:5A8BB08EFF0D416AAAD3B435B51404EE:85A2ED1CA59D0479B1E3406972AB1928:::` <br> `bert:501:C6E4266FEBEBD6A8AAD3B435B51404EE:0B9957E8BED733E0350C703AC1CDA822:::` <br> `admin:502:333CB006680FAF0A417EAF50CFAC29C3:D2EDBC29463C40E76297119421D2A707:::` | Fred: <br> Bert: <br> Admin: |


