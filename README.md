<div align="center">
<h1>So Power Automated Menu System (SPAMS)</h1>
</div>

### What this application does: 
- This is a Python application. <br />
- Main objective of this project is to implement cryptography to enhance its security feature <br />
- The server sends an encrypted menu to the client, the client decrypts it. <br />
- Next, the client sends an encrypted "end-of-the-day.csv" file to the server. <br />
- Which the server needs to decrypt. <br />
  
#


</div>

### Server items
- import socket ------------ # tcp protocol <br />
- import datetime ------------ # for composing date/time stamp <br />
- import sys ------------ # handle system error <br />
- import time ------------ # for delay purpose <br />
- import hashlib <br />
- import hmac <br />
- import os <br />
- import ssl <br />

#### Logging and monitoring features 
- import logging <br />
#### NTP synchronization
- import ntplib <br />

#### PyCryptodome
- from Crypto.Cipher import AES <br />
- from Crypto.Util.Padding import pad, unpad <br />
- from Crypto.Random import get_random_bytes <-- But I used fixed IV bytes for DEBUGGING purpose. This is not okay for real life!

#### RSA for non-repudiation
- from Crypto.Signature import PKCS1_v1_5 as pkcs1_15 <br />
- from Crypto.Hash import SHA256 <br />
- from Crypto.PublicKey import RSA <br />



### Client 
- import socket ------------ # tcp protocol <br />
- import datetime ------------ # for composing date/time stamp <br />
- import sys ------------ # handle system error <br />
- import traceback ------------ # for print_exc function <br />
- import time ------------ # for delay purpose <br />
- import hashlib <br />
- import hmac <br />
- import os <br />
- import select <br />
- import ssl <br />
- from threading import Thread <br />

#### Logging and monitoring features 
- import logging <br />
#### NTP synchronization
- import ntplib <br />

#### PyCryptodome
- from Crypto.Cipher import AES
- from Crypto.Util.Padding import pad
- from Crypto.Random import get_random_bytes

#### RSA for non-repudiation
- from Crypto.Signature import PKCS1_v1_5 as pkcs1_15 <br />
- from Crypto.Hash import SHA256 <br />
- from Crypto.PublicKey import RSA <br />

## Languagues and Tools
- Python
	- pycryptodome
- Visual Studio Code
