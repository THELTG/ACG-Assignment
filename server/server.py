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
# Koh Kai En       (P2104175)
# Lee Pin          (P2128610)
# SATHIAH ELAMARAN (P2129017)
#
# python3.10
# 
# required packages : Cryptodome, cryptography
# installation      : pip install pycryptodome
#                   : pip install cryptography
# 
# >>>>> SYNTAX >>>>>
# To run normally:
# python ./server.py
#
# To renew private and public keys with a different password:
# python ./server.py -r
#

# python imports
import logging
import os
import socket
import threading
import time
import sys
import datetime

# pyftpdlib imports
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# pycryptodome imports
from Cryptodome.Signature import DSS
from Cryptodome.PublicKey import DSA
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives import serialization    
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# argument parsing
lower = lambda x : x.lower()
arguments = [lower(i) for i in sys.argv]
arguments.pop(0)

def clearScreen():
    os.system("cls")
clearScreen()

# used to decrypt privatekey file
password = input("Enter decryptor password:")

# defining folder paths
fileServer = "data"
imageDir = "images"
unverifiedDir = "unverified"
logDir = "logs"

ftpLog = "ftp.log"
serverLog = "server.log"

# ensures that folders are in place
if not os.path.isdir(fileServer):
    os.mkdir(fileServer)

if not os.path.isdir(imageDir):
    os.mkdir(imageDir)

if not os.path.isdir(unverifiedDir):
    os.mkdir(unverifiedDir)

if not os.path.isdir(logDir):
    os.mkdir(logDir)

logFiles = os.listdir(logDir)

if ftpLog not in logFiles:
    open(f"./{logDir}/{ftpLog}","w").write("")

if serverLog not in logFiles:
    open(f"./{logDir}/{serverLog}","w").write("")

# FTP configurations and hosting
# changed FTP permissions to eadfw to allow changing of directories
# within the home folder
authorizer = DummyAuthorizer()
authorizer.add_user("cctvCountry","password",f"./{fileServer}/",perm="aw")
# initially authorizer.add_anonymous("./data/" , perm='adfmwM')
handler = FTPHandler
handler.authorizer = authorizer
server = FTPServer(("127.0.0.1", 2121), handler) # bind to high port, port 21 need root permission

# global real-time lists for operations
certificates = []
aes_keys = []
decryption_keys = []

# defining publickey and privatekey files
publicKeyFile = "public_cert.cer"
privateKeyFile = "private_key.der"


def manualLog(content):
    print(content)
    open(f"./{logDir}/{serverLog}","a").write(f"{datetime.datetime.now()} >>> {content}\n")

#  extracts nameattribute in certificate
def getNameStr(subj):
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
    serverConfirmed = "Client,DISM1B06,Singapore,SG"
    publicFound = certificate.public_key()
    if serverConfirmed != getNameStr(certificate.issuer):
        return False
    try:
        publicFound.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            certificate.signature_hash_algorithm
        )
    except Exception as e:
        print(e)
        return False
    
    if certificate.not_valid_after > datetime.datetime.now() > certificate.not_valid_before:
        return True

    else:
        return False

# generates a new certificate and privatekey
def genKey():
    manualLog("[SERVER]   Generating an RSA key pair...")
    pubk = open(publicKeyFile,"w")
    privk = open(privateKeyFile,"wb")

    rsakey_pair = rsa.generate_private_key(65537,2048)
    private_key = rsakey_pair.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.encode()))
    public_key = rsakey_pair.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Singapore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"DISM1B06"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Server")
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
        ).sign(rsakey_pair, hashes.SHA256())

    certificate = cert.public_bytes(serialization.Encoding.PEM).decode()

    pubk.write(certificate)
    #encrypt private key in the future
    privk.write(private_key)
    manualLog(f"[SERVER]   Generated a new key pair to {publicKeyFile} and {privateKeyFile}")
    pubk.close()
    privk.close()

def unresponsive():
        manualLog("[SERVER]   Connection closed")
        connection.close()

def receive() -> str:
    try:
        message = connection.recv(BUFFER).decode()
        return message
    except:
        manualLog("[SERVER]   Connection closed")
        return None

def send(message:str):
    try:

        connection.send(message.encode())
        time.sleep(0.5)
    except:
        manualLog("[SERVER]   Connection closed")
        connection.close()

# Key exchange server module
def startKeyServer():
    global BUFFER
    global connection
    
    HOST = "127.0.0.1"
    PORT  = 5656
    BUFFER = 128**2
    s = socket.socket()

    s.bind((HOST,PORT))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.listen(5)
    while True:
        connection, address = s.accept()
        send(pubk)
        time.sleep(0.2)
        try:
            client = receive().split("|")
            certificates.append(client[0])
            aes_keys.append(client[1])
        except:
            manualLog("[SERVER]   Information received invalid")
            connection.close()
            continue

        time.sleep(0.2)
        connection.close()
        manualLog("[SERVER]   Public Key exchange complete")

# FTP server hosting module
def startFTPServer():
    logging.basicConfig(filename='./logs/ftp.log', level=logging.INFO)
    server.serve_forever()
    logging.shutdown()

# decrypts RSA encrypted aes session key
def RSADecrypt(private_key:object,aes_key):
    try:
        aesKey = PKCS1_OAEP.new(private_key).decrypt(bytes.fromhex(aes_key)).decode()
        return aesKey
    except:
        return None

# decrypts the encrypted image that is stored in hexadecimal
def aesDecrypt(key:str,data:str):
    BLOCK_SIZE = 16
    init_vector = bytes.fromhex("0181fd5ad06ab26b41b9f3708b944849")
    try:
        data = bytes.fromhex(data)
        cipher = AES.new(key.encode(),AES.MODE_CBC,iv=init_vector)
        plain_text = unpad(cipher.decrypt(data),BLOCK_SIZE)
        return plain_text

    except:
        return None
    
# verifies the image with public key found in certificate
def DSAVerify(public_key:str,message:str,signature:str):
    hashed = SHA256.new(message.encode())
    signature = bytes.fromhex(signature)
    public_key = DSA.import_key(public_key)
    dsa = DSS.new(public_key,"fips-186-3")
    try:
        dsa.verify(hashed,signature)
        return True

    except ValueError:
        return False

def writeImage(directory,imagename,data):
    open(f"./{directory}/{imagename}","wb").write(data)

# main code that integrates everything together e.g decryption, file and certificate verification
def autoChecker():
    points = 0
    while True:
        # checks for new files in fileServer every 0.5 seconds
        time.sleep(0.5)
        directory = os.listdir(f"./{fileServer}")

        # fail-safe algorithm for when something fails
        if directory != [] and decryption_keys == [] or decryption_keys != [] and directory == []: #or decryption_keys != [] and directory == []:
            points += 1
            # checks if there is an unexpected file / transfer of keys
            if points == 3:
                points = 0
                for i in directory:
                    os.remove(f"./{fileServer}/{i}")
                for i in decryption_keys:
                    decryption_keys.pop()
                manualLog("[FATAL]    Unexpected loss of decryption_key(s) / gain of unknown file(s), resetting values. FTP intrusion suspected")
        else:
            points = 0

        # RSA decryption done here for AES session key
        if aes_keys != []:
            aes_key = RSADecrypt(private_key,aes_keys[0])
            
            if aes_key == None:
                manualLog("[FAIL]     AES key could not be unlocked using Server's Private Key")
            
            else:
                decryption_keys.append(aes_key)
                manualLog("[SERVER]   AES Key for decryption received")
                
            aes_keys.pop(0)
        
        # verification + decryption done here
        if directory != [] and decryption_keys != [] and certificates != []:

            # knows the file name
            filename = directory[0]

            # knows the decryption key
            key = decryption_keys[0]
            
            # knows the DSA public key
            cert = certificates [0]
            certificate = x509.load_pem_x509_certificate(cert.encode())
            public_key = certificate.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            valid = validCert(certificate)

            if valid:
                try:
                    manualLog(f"[SUCCESS]  Public Key certificate verified")
                    # splits ciphered msg and signature
                    message = open(f"./{fileServer}/{filename}","r").read().split("|")

                    # knows the cipher text + signature
                    cipher = message[0]
                    signature = message[1]

                    # decrypts image
                    image = aesDecrypt(key,cipher)

                    # verifies image
                    verified = DSAVerify(public_key,cipher,signature)
                except:
                    manualLog(f"[SERVER]   Unknown file in ./{fileServer}")
                    try:
                        os.remove(f"./{fileServer}/{filename}")
                    except:
                        pass
                    continue
                
                # deletes cipher text
                os.remove(f"./{fileServer}/{filename}")
                filename = filename.replace('.enc','.jpg')

                # creates new image
                if image != None and verified == True:
                    writeImage(f"./{imageDir}/",filename,image)
                    manualLog(f"[SUCCESS]  Image decrypted and verified, out > /{imageDir}/{filename}\n")
                
                elif image != None and verified == False:
                    writeImage(f"./{unverifiedDir}/",filename,image)
                    manualLog(f"[FAIL]     Image decrypted but unverified, out > /{unverifiedDir}/{filename}\n")

                else:
                    manualLog( "[FAIL]     Image could not be decrypted and was discarded\n")

            else:
                manualLog("[FAIL]     Client public key certificate invalid")
            
            # discards public key and decryption key
            certificates.pop(0)
            decryption_keys.pop(0)

# enable to be daemon service
# to allow thread to stop after sys.exit()

if "-r" in arguments:
    genKey()

else:
    # checking of pem files
    try:
        # see https://www.geeksforgeeks.org/try-except-vs-if-in-python/ to understand why i did it this way
        if os.path.getsize(publicKeyFile) == 0 or os.path.getsize(privateKeyFile) == 0:
            genKey()
    except:
        genKey()

pubk = open(publicKeyFile,'r').read()
privk = open(privateKeyFile,'rb').read()

global private_key

try:
    private_key = serialization.load_der_private_key(privk,password.encode()).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    private_key = RSA.import_key(private_key.decode())
    
except:
    manualLog("[SERVER]   Password incorrect")
    sys.exit(0)

keyServer = threading.Thread(target=startKeyServer,daemon=True)
ftpServer = threading.Thread(target=startFTPServer,daemon=True)

clearScreen()
manualLog("[SERVER]   Private Key Decrypted")
manualLog("[SERVER]   Starting...")

keyServer.start()
ftpServer.start()

autoChecker()