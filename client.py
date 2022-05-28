from encodings import utf_8
import socket
import os
import time
from tqdm import tqdm
from tkinter import *
import tkinter
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os
from Crypto.Util.Padding import pad
import customtkinter
from time import sleep
import multiprocessing
from tkinter.filedialog import askopenfilename
import sys


def clientFNC(host, port, message, type):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(type)
        data = s.recv(1024)
        s.close()
    print(f"Received {data!r}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message)
        data = s.recv(1024)
        s.close()
    print(f"Received {data!r}")


def clientFNCFile(host, port, fileName, type, fileSize, fileNameNotCoded):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(type.encode())
        data = s.recv(1024)
        s.close()
    print(f"sent data type {data}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Const
        SIZE = 1024 * 8
        # connect
        s.connect((host, port))

        # send filename and filesize
        data = f"{fileName}__{fileSize}"
        s.send(data.encode("utf-8"))
        print(f"file name and file size have been sent")
        print("sleeper")
        # transfer !!!
        bar = tqdm(
            range(os.path.getsize(fileNameNotCoded)),
            f"Sending {fileNameNotCoded}",
            unit="B",
            unit_scale=True,
            unit_divisor=SIZE,
        )
        with open(fileNameNotCoded, "rb") as f:
            tempVar = True
            while tempVar:
                data = f.read(SIZE)
                if not data:
                    break
                if len(data) < SIZE - 1:
                    tempVar = False
                if type == "fileCBC":
                    print(len(CipherMessageWithCBC(data)))
                    s.send(CipherMessageWithCBC(data))
                else:
                    # print(len(CipherMessageWithECB(data)))
                    s.send(CipherMessageWithECB(data))
                msg = s.recv(SIZE).decode("utf-8")
                bar.update(len(data))
        # close connection
        s.close()
    print(f"File was sent")


def CipherMessageWithECB(data):
    data = pad(data, AES.block_size)

    recipient_key = RSA.import_key(open("public_rec.pem").read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    ciphertext = cipher_aes.encrypt(data)

    text = enc_session_key + ciphertext

    return text


def CipherMessageWithCBC(data):
    # CBC CODE
    data = pad(data, AES.block_size)
    recipient_key = RSA.import_key(open("public_rec.pem").read())
    session_key = get_random_bytes(32)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key[0:16], AES.MODE_CBC, session_key[16:32])
    ciphertext = cipher_aes.encrypt(data)

    text = enc_session_key + ciphertext

    return text
