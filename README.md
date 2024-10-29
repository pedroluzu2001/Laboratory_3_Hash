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
| A.3 | Using: <br> Web link (Hashing): <br> [MD5 Hash](http://asecuritysite.com/encryption/md5) <br> Determine the number of hex characters for the hash signatures defined. Note: perhaps copy and paste your hash to an online character counter? | MD5 hex chars: 32 <br> SHA-1 hex chars: 40 <br> SHA-256 hex chars: 64 <br> SHA-384 hex chars: 96 <br> SHA-512 hex chars: 128 <br> How does the number of hex characters relate to the length of the hash signature? The number of hexadecimal characters needed to represent hash signatures varies with the hashing algorithm used. For example, MD5 produces a 128-bit (16-byte) hash requiring 32 hex characters, while SHA-1 generates a 160-bit (20-byte) hash that needs 40 hex characters. Similarly, SHA-256 outputs a 256-bit (32-byte) hash represented by 64 hex characters, SHA-384 yields a 384-bit (48-byte) hash needing 96 hex characters, and SHA-512 creates a 512-bit (64-byte) hash that requires 128 hex characters. In all cases, the number of hex characters is always double the number of bytes in the hash. |
| A.4 | For the following /etc/shadow file, determine the matching password: <br> bi11: \$apr1\$wazs/8Tm\$jDZmizBct/c2hysERcZ3m1 <br> mike: \$apr1\$mKfrJqUI\$Kx0CL9krmqhCu0SHKqp5Q0 <br> fred: \$apr1\$Jbe/hcIb\$/k3A4kjpJyC06BUUaPRKS0 <br> ian: \$apr1\$0GyPhsLi\$jTTzW0HNS4C15ZEoyFLjB. <br> jane: \$1\$rqOIRBBN\$R2pOQH9egTTVN1N1st2u7. <br> [Hint: `openssl passwd -aprl -salt ZaZS/8TF napier`] | The passwords are password, napier, inkwell, and Ankle123. <br> Bill's password: napier <br> Mike's password: Ankle123 <br> Fred's password: omkwell <br> Ian's password: paaword <br> Jane's password: anpier |
| A.5 | From Ubuntu, download the following: <br> Web link (Files): <br> [Files.zip](http://asecuritysite.com/files02.zip) <br> (a quick way to download is `wget asecuritysite.com/files02.zip`) and the files should have the following MD5 signatures: <br> MD5 (1.txt) = `5d41402abc4b2a76b9719d911017c592` <br> MD5 (2.txt) = `69faab6268350295550de7d587bc323d` <br> MD5 (3.txt) = `fea0f1f6fede90bd0a925b4194deac11` <br> MD5 (4.txt) = `d89b56f81cd7b82856231e662429bcf2` | Which file(s) have been modified?<br>e3fc91b12a36c2334ebb66caa2d75b |
| A.6 | From Ubuntu, download the following ZIP file: <br> Web link (PS Files): <br> [Letters.zip](http://asecuritysite.com/letters.zip) <br> (a quick way to download is `wget asecuritysite.com/letters.zip`) <br> On your Ubuntu instance, you should be able to view the files by double-clicking on them in the file explorer (as you should have a PostScript viewer installed). <br> `cat letter_of_rec.ps openssl md5` | Do the files have different contents? Yes <br> Now determine the MD5 signature for them. What can you observe from the result? The matching MD5 signatures in both casses occurs due to a collision. |


## B Hash Cracking (Hashcat)

| No   | Description | Result |
|------|-------------|--------|
| B.1 | Run the hashcat benchmark (e.g., `hashcat -b -m 0`), and complete the following: | Hash rate for MD5:438.3 MH/s (50.38ms)  <br> Hash rate for SHA-1: 120.7 MH/s (93.40ms) <br> Hash rate for SHA-256: 59955.5 kH/s <br> Hash rate for APR1: 123.8 kH/s (59.67ms) |
| B.2 | On Ubuntu, create a word file (`words`) with the words "napier", "password", "Ankle123", and "inkwell". <br> Using hashcat, crack the following MD5 signatures (`hash1`): <br> `232DD5D7274E0D662F36C575A3BD634C` <br> `5F4DCC3B5AA765D61D8327DEB882CF99` <br> `6D5875265D1979BDAD1C8A8F383C5FF5` <br> `04013F78ACCFEC9B673005FC6F20698D` <br> Command used: `hashcat -m 0 hash1 words` | 232DD...634C: <br> Is it `[napier]` <br> 5F4DC...CF99: <br> Is it `[password]` <br> 6D587...5FF5: <br> Is it `[Ankle123]` <br> 04013...698D: <br> Is it `[inkwell]`|
| B.3 | Using the method from the first part of this tutorial, find the following for names of fruits (all lowercase): <br> `FE01D67A002DFA0F3AC084298142ECCD` <br> `1F3870BE274F6C49B3E31A0C6728957F` <br> `72B302BF297A228A75730123EFEF7C41` <br> `8893DC16B1B2534BAB7B03727145A2BB` <br> `889560D93572D538078CE1578567B91A` | FE01D: orange <br> 1F387: apple <br> 72B30: banana <br> 8893D: pear <br> 88956: peach |
| B.4 | Put this SHA-256 value in a file named `file.txt`: <br> `106a5842fc5fce6f663176285ed1516dbb1e3d15c05abab12fdca46d60b539b7` <br> By adding a word "help" in a word file `words.txt`, prove that the following cracks the hash (where `file.txt` contains the hashed value): <br> `hashcat -m 1400 file.txt words.txt` |Session..........:hashcatStatus...........: Cracked<br>Hash.Mode........: 1400 (SHA2-256)<br>Hash.Target......: <br>106a5842fc5fce6f663176285ed1516dbb1e3d15c05a<br>bab12fd...b539b7<br>Time.Started.....: Sat Sep 16 17:49:08 2023 (0 secs)<br>Time.Estimated...: Sat Sep 16 17:49:08 2023 (0 secs)<br>Kernel.Feature...: Pure Kernel<br>Guess.Base.......: File (words.txt)<br>Guess.Queue......: 1/1 (100.00%)<br>Speed.#1.........: 921 H/s (0.07ms) @ Accel:128 <br>Loops:1 Thr:64 Vec:1<br>Recovered........: 1/1 (100.00%) Digests (total), 1/1 <br>(100.00%) Digests (new)<br>Progress.........: 5/5 (100.00%)<br>Rejected.........: 0/5 (0.00%)<br>Restore.Point....: 0/5 (0.00%)<br>Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1<br>Candidate.Engine.: Device Generator<br>Candidates.#1....: napier -> help<br>|
| B.5 | The following is an NTLM hash for "help": <br> `0333c27eb4b9401d91fef02a9f74840e` <br> Prove that the following can crack the hash (where `file.txt` contains the hashed value): <br> `hashcat -m 1000 file.txt words.txt` |Session..........:hashcatStatus...........: Cracked<br>Hash.Mode........: 1000 (NTLM) |

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
celtic
motherwell
Aaberdeen
livingston


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
Words: hair, face, eye
Number of tests for each sequence tried:

a->z: it tests all lowercase letters from 'a' to 'z'.
aa->zz: it tests all combinations of two lowercase letters from 'aa' to 'zz'.
aaa->zzz: it tests all combinations of three lowercase letters from 'aaa' to 'zzz'.
aaaa->zzzz: it tests all combinations of three lowercase letters from 'aaa' to 'zzz'.
What happens when you take the “--increment” flag away?
Hashcat will use specific masks or patterns that we provide with the ?l, ?l?l, ?l?l?l, and ?l?l?l?l 
options
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
Words: passwordW, password5

Number of tests for each:
26 tests for passwordW
10 tests for password5

```

## C  Hashing Cracking (John The Ripper)

All of the passwords in this section are in lowercase.


| No   | Description | Result |
|------|-------------|--------|
| C.1 | On Ubuntu, and using John the Ripper with a word list containing fruit names, crack the following `pwdump` passwords: <br> `fred:500:E79E56A8E5C6F8FEAAD3B435B51404EE:5EBE7DFA074DA8EE8AEF1FAA2BBDE876:::` <br> `bert:501:10EAF413723CBB15AAD3B435B51404EE:CA8E025E9893E8CE3D2CBF847FC56814:::` | Fred: apple<br> Bert: orange |
| C.2 | On Ubuntu, and using John the Ripper, crack the following `pwdump` passwords (they are names of major Scottish cities/towns): <br> `Admin:500:629E2BA1C0338CE0AAD3B435B51404EE:9408CB400B20ABA3DFEC054D2B6EE5A1:::` <br> `fred:501:33E58ABB4D723E5EE72C57EF50F76A05:4DFC4E7AA65D71FD4E06D061871C05F2:::` <br> `bert:502:BC2B6A869601E4D9AAD3B435B51404EE:2D8947D98F0B09A88DC9FCD6E546A711:::` | Admin: dundee <br> Fred: aberdeen <br> Bert: perth |
| C.3 | On Ubuntu, and using John the Ripper, crack the following `pwdump` passwords (they are the names of animals): <br> `fred:500:5A8BB08EFF0D416AAAD3B435B51404EE:85A2ED1CA59D0479B1E3406972AB1928:::` <br> `bert:501:C6E4266FEBEBD6A8AAD3B435B51404EE:0B9957E8BED733E0350C703AC1CDA822:::` <br> `admin:502:333CB006680FAF0A417EAF50CFAC29C3:D2EDBC29463C40E76297119421D2A707:::` | Fred: snake <br> Bert: tiger <br> Admin: elephant |


Note:

`Use rm -r ~/.john/ to remove the previously cracked hashes.`

You can use john --wordlist=fruits pwdump to crack with a wordlist and pwdump.

## D LM Hash

The LM Hash is used in Microsoft Windows. For example, for LM Hash:

```
hashme gives:           ` FA-91-C4-FD-28-A2-D2-57-AA-D3-B4-35-B5-14-04-EE`

network gives:           `D7-5A-34-5D-5D-20-7A-00-AA-D3-B4-35-B5-14-04-EE`

napier gives:           ` 12-B9-C5-4F-6F-E0-EC-80-AA-D3-B4-35-B5-14-04-EE`

```


Notice that the right-most element of the hash are always the same, if the password is less
than eight characters. With more than eight characters we get:

```
networksims gives:             `D7-5A-34-5D-5D-20-7A-00-38-32-A0-DB-BA-51-68-07`

napier123 gives:               `67-82-2A-34-ED-C7-48-92-B7-5E-0C-8D-76-95-4A-50`

```
For “hello” we get:

``` 
LM:          `FD-A9-5F-BE-CA-28-8D-44-AA-D3-B4-35-B5-14-04-EE`

NTLM:        `06-6D-DF-D4-EF-0E-9C-D7-C2-56-FE-77-19-1E-F4-3C`

```

We can check these with a Python script:

```
import passlib.hash;
string="hello"
print ("LM Hash:"+passlib.hash.lmhash.hash(string))
print ("NT Hash:"+passlib.hash.nthash.hash(string))
```


which gives:
 ```
LM Hash:fda95fbeca288d44aad3b435b51404ee
NT Hash:066ddfd4ef0e9cd7c256fe77191ef43c
```

 Web link (LM Hash): http://asecuritysite.com/encryption/lmhash

 
| No  | Description | Result |
| --- | ----------- | ------ |
| D.1 |Create a Python script to determine the LM hash and NTLM hash of the following words | "Napier"<br>LM Hash:<br> 12b9c54f6fe0ec80aad3b435b51404ee<br> NTLM Hash:<br> d0b72d7d45c68cde9f8a2bef0b7f9451  <br>"Foxtrot"<br>LM Hash:<br> f660c87bce347579aad3b435b51404ee<br> NTLM Hash:<br> 85b402f72c46d34901de59d9b049280d |

## E APR1

The Apache-defined APR1 format addresses the problems of brute forcing an MD5 hash, and 
basically iterates over the hash value 1,000 times. This considerably slows an intruder as they 
try to crack the hashed value. The resulting hashed string contains “$apr1$” to identify it and 
uses a 32-bit salt value. We can use both htpassword and Openssl to compute the hashed 
string (where “bill” is the user and “hello” is the password):

```
# htpasswd -nbm bill hello
bill:$apr1$PkWj6gM4$XGWpADBVPyypjL/cL0XMc1
# openssl passwd -apr1 -salt PkWj6gM4 hello
$apr1$PkWj6gM4$XGWpADBVPyypjL/cL0XMc1
```
We can also create a simple Python program with the passlib library, and add the same salt as 
the example above:
```
import passlib.hash;
salt="PkWj6gM4"
string="hello"
print ("APR1:"+passlib.hash.apr_md5_crypt.hash(string, salt=salt))
```
We can created a simple Python program with the passlib library, and add the same salt as the 
example above:

`APR1:$apr1$PkWj6gM4$XGWpADBVPyypjL/cL0XMc1`

Refer to: http://asecuritysite.com/encryption/apr1

| No  | Description | Result |
| --- | ----------- | ------ |
| E.1 | Create a Python script to create the APR1 hash for the following:<br> [just list first four characters of the hash]| “changeme”:V2w1<br>“123456”:opHu<br>“password”OupR|

## F  SHA

While APR1 has a salted value, the SHA-1 hash does not have a salted value. It produces a 160-bit signature, thus can contain a larger set of hashed value than MD5, but because there is no salt it can be cracked to rainbow tables, and also brute force. The format for the storage of the hashed password on Linux systems is:

```
# htpasswd -nbs bill hello
bill:{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00=
```
We can also generate salted passwords with crypt, and can use the Python script of:

```
import passlib.hash;
salt="8sFt66rZ"
string="hello"
print ("SHA1:"+passlib.hash.sha1_crypt.hash(string, salt=salt))
print ("SHA256:"+passlib.hash.sha256_crypt.hash(string, salt=salt))
print ("SHA512:"+passlib.hash.sha512_crypt.hash(string, salt=salt))
```
SHA-512 salts start with $6$ and are up to 16 chars long.

SHA-256 salts start with $5$ and are up to 16 chars long


Which produces:

```
SHA1:$sha1$480000$8sFt66rZ$klAZf7IPWRN1ACGNZIMxxuVaIKRj
SHA256:$5$rounds=535000$8sFt66rZ$.YYuHL27JtcOX8WpjwKf2VM876kLTGZHsHwCBbq9x
TD
SHA512:$6$rounds=656000$8sFt66rZ$aMTKQHl60VXFjiDAsyNFxn4gRezZOZarxHaK.TcpV
YLpMw6MnX0lyPQU06SSVmSdmF/VNbvPkkMpOEONvSd5Q1
```
| No  | Description | Result |
| --- | ----------- | ------ |
| F.1 | Create a Python script to create the SHA for the following:<br> [just list first four characters of the hash]| “changeme”:<br>SHA1: dNfL <br>SHA256: yNCV <br>SHA512: B/.M <br>“123456”:<br>SHA1: RndE <br>SHA256: rAkO <br>SHA512: cGaB <br>“password”<br>SHA1: h0Q0 <br>SHA256: 63Ab <br>SHA512: hiU3|

## G PBKDF2
PBKDF2 (Password-Based Key Derivation Function 2) is defined in RFC 2898 and generates 
a salted hash. Often this is used to create an encryption key from a defined password, and where 
it is not possible to reverse the password from the hashed value. It is used in TrueCrypt to 
generate the key required to read the header information of the encrypted drive, and which 
stores the encryption keys.


PBKDF2 is used in WPA-2 and TrueCrypt (Using TrueCrypt is not secure). Its main focus is 
to produced a hashed version of a password and includes a salt value to reduce the opportunity 
for a rainbow table attack. It generally uses over 1,000 iterations in order to slow down the 
creation of the hash, so that it can overcome brute force attacks. The generalise format for 
PBKDF2 is:


DK = PBKDF2(Password, Salt, MInterations, dkLen)


where Password is the pass phrase, Salt is the salt, MInterations is the number of iterations, 
and dklen is the length of the derived hash.

In WPA-2, the IEEE 802.11i standard defines that the pre-shared key is defined by:
PSK = PBKDF2(PassPhrase, ssid, ssidLength, 4096, 256)

In TrueCrypt we use PBKDF2 to generate the key (with salt) and which will decrypt the 
header, and reveal the keys which have been used to encrypt the disk (using AES, 3DES or 
Twofish). We use:

byte[] result = passwordDerive.GenerateDerivedKey(16, ASCIIEncoding.UTF8.GetBytes(message), salt, 1000);

which has a key length of 16 bytes (128 bits - dklen), uses a salt byte array, and 1000 
iterations of the hash (Minterations). The resulting hash value will have 32 hexadecimal 
characters (16 bytes)

```
import passlib.hash;
import sys;
salt="ZDzPE45C"
string="password"
if (len(sys.argv)>1):
string=sys.argv[1]
if (len(sys.argv)>2): salt=sys.argv[2]
print ("PBKDF2 (SHA1):",passlib.hash.pbkdf2_sha1.hash(string, salt=salt.encode()))
print ("PBKDF2 (SHA256):",passlib.hash.pbkdf2_sha256.hash(string,salt=salt.encode()))
```

| No   | Description | Result |
|------|-------------|--------|
| G.1 | Create a Python script to create the PBKDF2 hash for the following (uses a salt value of “ZDzPE45C”). You just need to list the first six hex characters of the hashed value.|  For the password "changeme":<br>PBKDF2 (SHA1) First Six Characters: qS7S53<br>PBKDF2 (SHA256) First Six Characters: gWsN0J<br>For the password "123456":<br>PBKDF2 (SHA1) First Six Characters: Ax363N<br>PBKDF2 (SHA256) First Six Characters: GHyI8v<br>For the password "password":<br>PBKDF2 (SHA1) First Six Characters: .L1L.A<br>PBKDF2 (SHA256) First Six Characters: pd1VbF|
| G.2 | Create a Python script that uses the Argon2 algorithm for password derivation and verification operations. |Why is Argon2 considered more secure than some of its predecessors, such as PBKDF2?<br>Argon2 is more secure than PBKDF2 due to its memory-hard design, making it resistant to hardware attacks and time-memory trade-offs. It adapts easily with adjustable settings to meet changing security needs. Its win in the Password Hashing Competition (PHC) highlights its strength, making Argon2 a top choice for modern password hashing against advanced threats.|

## H Bcrypt
MD5 and SHA-1 produce a hash signature, but this can be attacked by rainbow tables. Bcrypt 
(Blowfish Crypt) is a more powerful hash generator for passwords and uses salt to create a nonrecurrent hash. It was designed by Niels Provos and David Mazières, and is based on the 
Blowfish cipher. It is used as the default password hashing method for BSD and other systems.

Overall it uses a 128-bit salt value, which requires 22 Base-64 characters. It can use a number 
of iterations, which will slow down any brute-force cracking of the hashed value. For example, 
“Hello” with a salt value of “$2a$06$NkYh0RCM8pNWPaYvRLgN9.” gives:
```
$2a$06$NkYh0RCM8pNWPaYvRLgN9.LbJw4gcnWCOQYIom0P08UEZRQQjbfpy
```

As illustrated in Figure 1, the first part is "$2a$" (or "$2b$"), and then followed by the number 
of rounds used. In this case is it 6 rounds which is 2^6 iterations (where each additional round 
doubles the hash time). The 128-bit (22 character) salt values comes after this, and then finally 
there is a 184-bit hash code (which is 31 characters). 

The slowness of bcrypt is highlighted with an AWS EC2 server benchmark using hashcat:
```
• Hash type: MD5 Speed/sec: 380.02M words
• Hash type: SHA1 Speed/sec: 218.86M words
• Hash type: SHA256 Speed/sec: 110.37M words
• Hash type: bcrypt, Blowfish(OpenBSD) Speed/sec: 25.86k words
• Hash type: NTLM. Speed/sec: 370.22M words
```
You can see that Bcrypt is almost 15,000 times slower than MD5 (380,000,000 words/sec 
down to only 25,860 words/sec). With John The Ripper:
```
• md5crypt [MD5 32/64 X2] 318237 c/s real, 8881 c/s virtual
• bcrypt ("$2a$05", 32 iterations) 25488 c/s real, 708 c/s virtual
• LM [DES 128/128 SSE2-16] 88090K c/s real, 2462K c/s virtual
```
where you can see that BCrypt over 3,000 times slower than LM hashes. So, although the main 
hashing methods are fast and efficient, this speed has a down side, in that they can be cracked 
easier. With Bcrypt the speed of cracking is considerably slowed down, with each iteration 
doubling the amount of time it takes to crack the hash with brute force. If we add one onto the 
number of rounds, we double the time taken for the hashing process. So, to go from 6 to 16 
increase by over 1,000 (210) and from 6 to 26 increases by over 1 million (220).


The following defines a Python script which calculates a whole range of hashes:

```
# https://asecuritysite.com/encryption/hash
import sys
from hashlib import md5
import passlib.hash;
import bcrypt
import hashlib;
num = 30
repeat_n=1
11
salt="ZDzPE45C"
string="the boy stood on the burning deck"
salt2="1111111111111111111111"
print ("Word: ",string)print ("Salt: ",salt)
print("\nHashes")
print("SHA-1\t",hashlib.sha1(string.encode()).hexdigest())
print("SHA-256\t",hashlib.sha256(string.encode()).hexdigest()) print("SHA-512\t",hashlib.sha512(string.encode()).hexdigest())
print("MD-5:\t\t\t", md5(string.encode()).hexdigest())
print("DES:\t\t\t", passlib.hash.des_crypt.hash(string.encode(), salt=salt[:2]))
print("Bcrypt:\t\t\t", 
bcrypt.kdf(string.encode(),salt=salt.encode(),desired_key_bytes=32,rounds=100 
).hex())
print("APR1:\t\t\t", passlib.hash.apr_md5_crypt.hash(string.encode(), salt=salt))
print("PBKDF2 (SHA1):\t\t", passlib.hash.pbkdf2_sha1.hash(string.encode(),rounds=5, salt=salt.encode())) 
print("PBKDF2 (SHA-256):\t", passlib.hash.pbkdf2_sha256.hash(string,rounds=5, salt=salt.encode())) 
```


| No   | Description | Result |
|------|-------------|--------|
| H.1 |Create the hash for the word “hello” for the different methods (you only have to give the first six hex characters for the hash):<br>Also note the number hex characters that the hashed value uses:|MD5: 5d4140<br>SHA1: aaf4c6<br>SHA256: 2cf24d<br>SHA512: 9b71d2<br>DES: ZDVX7N<br>Bcrypt:67e6b6<br>Apr1:qn6wBl<br>PBKDF2(SHA1): HEZFFxE<br>PBKDF2 (SHA-256): 46kLMg |

![image](https://github.com/user-attachments/assets/071259e8-49eb-4361-9de1-0e45d3ec2266)


## I HMAC 

Write a Python program which will prove the following 
```
Data: Hello
Hex: 48656c6c6f
Key: qwerty123
Hex: 717765727479313233
HMAC-MD5: c3a2fa8f20dee654a32c30e666cec48e w6L6jyDe5lSjLDDmZs7Ejg==
```
If you get this to work, can you expand to include other MAC methods (including HMACSHA1, HMAC-256, and so on). A starting point for your program is here:

https://asecuritysite.com/hash/hashnew2_hmacmd5

Using this online tool, check that the HMAC values are correct: 

https://cryptii.com/pipes/hmac

```
parser = argparse.ArgumentParser(description="Calculate HMAC hash for a given input and key.")
parser.add_argument("data", type=str, help="Input data")
parser.add_argument("key", type=str, help="HMAC key")
parser.add_argument("--hash", type=str, default="SHA256", help="Hash algorithm (default: SHA256)")


args = parser.parse_args()

try:
    # Convertir los datos de entrada y la clave en bytes
    data = args.data.encode()
    key = args.key.encode()


    print("Data:", args.data)
    print(" Hex:", binascii.b2a_hex(data).decode())
    print("Key:", args.key)
    print(" Hex:", binascii.b2a_hex(key).decode())
    print()


    if args.hash == "MD5":
        show_hash("MD5", hashes.MD5(), data, key)
    elif args.hash == "SHA1":
        show_hash("SHA-1", hashes.SHA1(), data, key)
    elif args.hash == "SHA224":
        show_hash("SHA-224", hashes.SHA224(), data, key)
    elif args.hash == "SHA256":
        show_hash("SHA-256", hashes.SHA256(), data, key)
    elif args.hash == "SHA512":
        show_hash("SHA-512", hashes.SHA512(), data, key)
    else:
        print("Unsupported hash algorithm:", args.hash)

except Exception as e:
    print(e)
```

## J Reflective statements
```
1. Why might increasing the number of iterations be a better method of protecting 
a hashed password than using a salted version?

Increasing the number of iterations makes a hashed password harder to crack by requiring more computational effort per attempt, whereas adding a salt only prevents precomputed attacks like rainbow tables but doesn’t slow down the hashing process itself.
```

```
2. Why might the methods bcrypt, Argon2, Scrypt be preferred for storing 
passwords than MD5, SHA, Phpass and PBFDK2?
Bcrypt, Argon2, and Scrypt are preferred for password storage because they are designed to be slow and memory-intensive, resisting brute-force attacks effectively. MD5, SHA, Phpass, and PBKDF2 are faster and lack the same level of memory-hardness, making them less secure against modern attack methods.

```




