import sys
import socket
import selectors
import types
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os
from Crypto.Util.Padding import pad, unpad
import customtkinter
import serverFile
from client import clientFNC
import multiprocessing
from time import sleep

sel = selectors.DefaultSelector()

type = ""

def GetPublicKey(data):
    file_out = open("public_rec.pem", "w")
    file_out.write(data.decode())
    file_out.close()

def DecipherMessageWithECB(data):
    # dataStr = data.decode()
    file_out = open("encrypted_data.bin", "wb")
    file_out.write(data)
    file_out.close()
    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("RSApriv/private.pem").read())

    enc_session_key, ciphertext = [
        file_in.read(x) for x in (private_key.size_in_bytes(), -1)
    ]

    file_in.close()
    os.remove("encrypted_data.bin")
    
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    data = cipher_aes.decrypt(ciphertext)
    print(unpad(data,AES.block_size).decode())


def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)


def service_connection(key, mask):
    global type
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Should be ready to read
        if recv_data:
            data.outb += recv_data
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            print(f"Echoing {data.outb!r} to {data.addr}\n")
            if type == "key":
                GetPublicKey(data.outb)
            if type == "message":
                DecipherMessageWithECB(data.outb)
            if type == "":
                if data.outb.decode() == "message":
                    type = "message"
                if data.outb.decode() == "key":
                    type = "key"
        

            # print(f"Echoing {data.outb!r} to {data.addr}")
            sent = sock.send(data.outb)  # Should be ready to write
            data.outb = data.outb[sent:]


def serverStart(host, port):
    # host, port = sys.argv[1], int(sys.argv[2])
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((host, port))
    lsock.listen()
    print(f"Listening on {(host, port)}")
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    service_connection(key, mask)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()
