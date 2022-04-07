from base64 import b64decode, b64encode
from doctest import master
from tkinter import *
from tkinter import Tk, Label, Button,ttk
from typing import List
import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os
from Crypto.Util.Padding import pad,unpad
import customtkinter

customtkinter.set_appearance_mode("gray")
customtkinter.set_default_color_theme("green") 

class User:
    def __init__(self, name:str):
        self.name:str = name

class UserHandler:
    def __init__(self):
        self.listOfUsers:List[User] = []

    def addUser(self, user:User):
        self.listOfUsers.append(user)

class ViewHandler:
    def __init__(self, master):
        self.master = master
        master.title("QuickM")

    def addLabels(self, userlist):
        for user in userlist:
            self.label = customtkinter.CTkLabel(self.master, text=user.name)
            self.label.pack()
            
            self.greet_button = customtkinter.CTkButton(self.master, text="Greet", command=lambda user = user: self.greet(user))
            self.greet_button.pack()

        #ttk.Button(self.master, text="Open", command=self.open_win).pack()


    def greet(self, user):
        self.open_win()
        action = ActionWindow(self.master, user)
        action.addLabels()

    def open_win(self):
        self.master.destroy()
        self.master = customtkinter.CTk()
        self.master.geometry("852x480")
    

class ActionWindow:
    def __init__(self, master, user:User):
        self.master = master
        master.title("QuickM")
        self.user = user

    def napisz(self):
        print("XD")

    def addLabels(self):
        self.label = customtkinter.CTkLabel(self.master, text=self.user.name)
        self.label.pack()
        Button(self.master, text="Open", command=self.napisz).pack()

def GenerateRSAKeys():

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    os.mkdir("RSApriv")
    file_out = open("RSApriv/private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    os.mkdir("RSApub")
    file_out = open("RSApub/public.pem", "wb")
    file_out.write(public_key)
    file_out.close()
# def pad_message(message):
#   while len(message) % 16 != 0:
#     message = message + " "
#   return message

def CipherMessageWithECB():
    data = "I met aliens in UFO. Here is the map."
    data = pad(data.encode("utf-8"),AES.block_size)
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("RSApub/public.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    ciphertext= cipher_aes.encrypt(data)
    [ file_out.write(x) for x in (enc_session_key,  ciphertext) ]
    file_out.close()

def DecipherMessageWithECB():
    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("RSApriv/private.pem").read())

    enc_session_key, ciphertext = \
    [ file_in.read(x) for x in (private_key.size_in_bytes(), -1) ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    data = cipher_aes.decrypt(ciphertext)
    print(data.decode("utf-8"))


def Test():
    data = "I met aliens in UFO. Here is the map."
    data = pad(data.encode('utf-8'),AES.block_size)
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("RSApub/public.pem").read())
    session_key = get_random_bytes(AES.block_size)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(cipher_rsa, AES.MODE_CBC, session_key)
    ciphertext = cipher_aes.encrypt(data,AES.block_size)
    [ file_out.write(x) for x in ( enc_session_key,b64encode(enc_session_key + ciphertext )) ]
    file_out.close()
    # def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC): 
    # IV = "A"*16  #We'll manually set the initialization vector to simplify things 
    # aes = AES.new(key, mode, IV) 
    # new_data = aes.encrypt(data) 
    # return new_data 
def detest():
    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("RSApriv/private.pem").read())

    enc_session_key,ciphertext = \
    [ file_in.read(x) for x in (private_key.size_in_bytes(), -1) ]

    raw = b64decode(ciphertext)
    

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_CBC,raw[:AES.block_size])
    data =  unpad(cipher_aes.decrypt(raw[:AES.block_size]),AES.block_size)
    print(data)

def main():
    # if not(os.path.exists('RSApriv')):
    #     GenerateRSAKeys()
    root = customtkinter.CTk()
    root.geometry('852x480')
    userHandler = UserHandler()
    for i in range (5):
        userHandler.addUser(User(str(i)))
    my_gui = ViewHandler(root)
    my_gui.addLabels(userHandler.listOfUsers)
    root.mainloop()
    # Test()
    # detest()


if __name__ == "__main__":
    main()