from base64 import b64decode, b64encode
from doctest import master
from faulthandler import disable
from time import sleep
from tkinter import *
from typing import List
import socket
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os
from Crypto.Util.Padding import pad,unpad
from matplotlib.pyplot import text
import customtkinter
import serverFile
import threading
import multiprocessing

customtkinter.set_appearance_mode("gray")
customtkinter.set_default_color_theme("green") 

def serverInit(root):
    # serverThread = threading.Thread(target = serverFile.Server,args = ("127.0.0.1",54321,))
    # serverThread.start()
    root.greet_button.state = DISABLED
    serverThread = multiprocessing.Process(target = serverFile.Server,args = ("127.0.0.1",54321,))
    serverThread.start()
    sleep(5)
    serverThread.terminate()
    # root.greet_button.state = NORMAL

def main():
    # if not(os.path.exists('RSApriv')):
    #     GenerateRSAKeys()
    root = customtkinter.CTk()
    root.geometry('852x480')
    my_string_var = StringVar()
    my_string_var.set("What should I learn")
    root.greet_button = customtkinter.CTkButton(text="Odpal Server", command=lambda: serverInit(root), state = NORMAL)
    root.greet_button.pack()
    root.my_label = customtkinter.CTkLabel(root,
                    textvariable = my_string_var)
    root.my_label.pack()
    root.greet_button2 = customtkinter.CTkButton(text="Wyslij wiadomość", command= serverInit)
    root.greet_button2.pack()
    print("xd")
    sleep(1)
    root.mainloop()
    # Test()


if __name__ == "__main__":
    main()