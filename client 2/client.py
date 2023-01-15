#   /$$$$$$   /$$$$$$   /$$$$$$         /$$$$$$   /$$$$$$   /$$$$$$ 
#  /$$__  $$ /$$__  $$ /$$__  $$       /$$__  $$ /$$__  $$ /$$__  $$
# | $$  \ $$| $$  \__/| $$  \__/      | $$  \__/| $$  \ $$|__/  \ $$
# | $$$$$$$$| $$      | $$ /$$$$      | $$      | $$$$$$$$  /$$$$$$/
# | $$__  $$| $$      | $$|_  $$      | $$      | $$__  $$ /$$____/ 
# | $$  | $$| $$    $$| $$  \ $$      | $$    $$| $$  | $$| $$      
# | $$  | $$|  $$$$$$/|  $$$$$$/      |  $$$$$$/| $$  | $$| $$$$$$$$
# |__/  |__/ \______/  \______/        \______/ |__/  |__/|________/
#
# DISM1B06
# Koh Kai En (P2104175)
# Lee Pin    (P2128610)
#
# python3.10
# 
# required packages : Cryptodome
# installation      : pip install pycryptodome
# 
# >>>>> SYNTAX >>>>>
# To run normally:
# python ./client.py
#
# To renew private and public key with a different passwords:
# python ./client.py -r
#
# To not sign image when sending encrypted image
# python ./client.py -d
#

# python imports
import base64
import time
import datetime
import ftplib
import io
import os
import sys
import socket
import string
import random

# pycryptodome imports
from Cryptodome.Cipher import PKCS1_OAEP

from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey import DSA
from Cryptodome.Signature import DSS

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

# cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization    
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



# argument parsing
lower = lambda x : x.lower()
arguments = [lower(i) for i in sys.argv]
arguments.pop(0)

def clearScreen():
    os.system("cls")
clearScreen()
# b64 message is the image
message = "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"

# defining publickey and privatekey files
publicKeyFile = "public_cert.cer"
privateKeyFile = "private_key.der"
server_PU = ""

# used to decrypt privatekey file
password = input("Enter decryptor password: ")

# generates a random 16 byte key for AES session key
def genRandPassword():
    charset = string.ascii_letters + string.digits
    out = ""
    # randomly generates with relation to the charset
    for i in range(16):
        out += random.choice(charset)
    return out

# checks if private and public keys are available and not empty
def genKey():
    print("Generating a DSA key pair...")
    # overwrites or creates a new pair
    pubk = open(publicKeyFile,"w")
    privk = open(privateKeyFile,"wb")

    dsakey_pair = dsa.generate_private_key(2048)

    public_key = dsakey_pair.public_key()
    private_key = dsakey_pair.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.encode()))
    
    # x.509 RSA self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DISM1B06"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Client")
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now()
        ).not_valid_after(
            # this cert is valid for 5 days
            datetime.datetime.now() + datetime.timedelta(5)
        ).sign(dsakey_pair, hashes.SHA256())

    certificate = cert.public_bytes(serialization.Encoding.PEM).decode()

    pubk.write(certificate)
    privk.write(private_key)

    print(f"Generated a new DSA key pair to {publicKeyFile} and {privateKeyFile}")
    pubk.close()
    privk.close()

# encrypts data in bytes with a 16 byte key in string
def aesEncrypt(key:str,data:bytes):
    BLOCK_SIZE = 16
    # customized initialization vector
    init_vector = bytes.fromhex("0181fd5ad06ab26b41b9f3708b944849")
    cipher = AES.new(key.encode(),AES.MODE_CBC,iv=init_vector)
    cipher_text = cipher.encrypt(pad(data,BLOCK_SIZE))
    return cipher_text.hex()

# deals when server is down
def unresponsive():
    print("server offline or unresponsive")
    sys.exit(0)

# receives input from server
def receive() -> str:
    s.settimeout(10)
    try:    
        message = s.recv(BUFFER).decode()
        return message
    except:
        unresponsive()

# sends messages to server
def send(message:str):
    try:
        s.send(message.encode())
        time.sleep(0.5)
    except:
        unresponsive()

# ftps file to server
def connect_server_send( file_name , file_data):   
    try:
        ftp = ftplib.FTP()  # use init will using port 21 , hence use connect()
        ftp.connect( SERVER , FTP_PORT )
        ftp.login("cctvCountry","password")
        #ftp.login()  # ftp.login(user="anonymous", passwd = 'anonymous@')
        stream_str = io.BytesIO( file_data )
        ftp.storbinary('STOR ' + file_name, stream_str  )
        ftp.quit()
    except Exception as e:
        print( e )

# encrypts the b64 decoded image
def get_picture(key):
    global times_of_image_request
    image = base64.b64decode(message)
    # encrypts the bytes of the image
    output = aesEncrypt(key,image)
    return output

# encrypts AES session key using RSA with server's public key
def RSAEncrypt(public_key:str,aes_key:str):
    pk = RSA.import_key(public_key)
    aesKey = PKCS1_OAEP.new(pk).encrypt(aes_key.encode())
    printableKey = aesKey.hex()
    return printableKey

# hashes and signs AES encrypted image
def DSASign(private_key:object,message:str):
    dsa = DSS.new(private_key,"fips-186-3")
    signedMessage = dsa.sign(SHA256.new(message.encode())).hex()
    return signedMessage

# finds NameAttributes in x509 certificate
def getNameStr(subj:x509.Certificate.issuer):
    ans=[]
    lst= [
        ('CN', NameOID.COMMON_NAME ),
        ('OU',NameOID.ORGANIZATIONAL_UNIT_NAME),
        ('O',NameOID.ORGANIZATION_NAME),
        ('L',NameOID.LOCALITY_NAME),
        ('ST',NameOID.STATE_OR_PROVINCE_NAME),
        ('C',NameOID.COUNTRY_NAME)
        ]
    for i in lst:
        attribute = subj.get_attributes_for_oid(i[1])
        if attribute:
            ans.append(f"{attribute[0].value}")

    return ",".join(ans)

# validates the certificate
def validCert(certificate:x509.Certificate):
    serverConfirmed = "Server,DISM1B06,Singapore,SG"
    publicFound = certificate.public_key()
    if serverConfirmed != getNameStr(certificate.issuer):
        return False
    try:
        publicFound.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm
            )
    except:
        return False
    
    if certificate.not_valid_after > datetime.datetime.now() > certificate.not_valid_before:
        return True

    else:
        return False

# renews private and public keys
if "-r" in arguments:
    genKey()

else:
    # tests to see if pem files exist AND the file size is != 0
    try:
        # see https://www.geeksforgeeks.org/try-except-vs-if-in-python/ to understand why i did it this way
        if os.path.getsize(publicKeyFile) == 0 or os.path.getsize(privateKeyFile) == 0:
            genKey()
    except:
        genKey()

# read only
pubk = open(publicKeyFile,'r').read()
privk = open(privateKeyFile,'rb').read()

try:
    # attempt loading encrypted DSA key
    global private_key

    # converts DER to PEM in cryptography library
    # then transfers privatekey to pycryptodome usables
    private_key = serialization.load_der_private_key(privk,password.encode()).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    private_key = DSA.import_key(private_key.decode())

except:
    # failure to decrypt means wrong passphrase
    print("password incorrect, please try again")
    sys.exit(0)
print("success...")

# sets up a socket relation to the server
SERVER = "127.0.0.1"
FTP_PORT = 2121
KEY_PORT = 5656
BUFFER = 4096

times_sent = 0


while True:
    times_sent += 1
    server_pubk = ""
    s = socket.socket()

    # start encryption
    # get random 16 byte aes key
    aesKey = genRandPassword()

    try:
        # connects to server
        s.connect((SERVER,KEY_PORT))
        
        # get server public key
        server_pubk = receive()
        certificate = x509.load_pem_x509_certificate(server_pubk.encode()) 
        valid = validCert(certificate)
        server_pubk = certificate.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.PKCS1).decode()
        if valid:

            # encrypt aes key with server public key
            aesRsa = RSAEncrypt(server_pubk,aesKey)
            clientPubk = x509.load_pem_x509_certificate(pubk.encode())
            # sends RSA public certificate with RSA-AES session key
            send(f"{pubk}|{aesRsa}")
        
        else:
            print("server sent public key certificate is invalid or expired")
            seconds = 10
            for i in range(seconds):
                print(f"trying again in {seconds - i} seconds")
                time.sleep(1)
            continue

    except Exception as e:
        # server unresponsive or dead
        unresponsive()

    # encrypts image
    my_image = get_picture(aesKey)
    f_name = datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S.enc" )

    if "-d" in arguments:
        my_signature = ""
        
    else:
        # signs encrypted image
        my_signature = DSASign(private_key,my_image)
        
    # appends signature to the back of ciphered image
    f_data = f"{my_image}|{my_signature}".encode()

    # sends full package to server
    connect_server_send( f_name , f_data )
    prompt = input(f"Sent {times_sent} image(s)... Enter anything to send again")

    seconds = 3
    for i in range(seconds):
        print(f"trying again in {seconds - i} seconds")
        time.sleep(1)
    continue