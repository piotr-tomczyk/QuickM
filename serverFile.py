import socket
import selectors
import types
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os
from Crypto.Util.Padding import unpad
import messagePopUp

sel = selectors.DefaultSelector()

type = ""


def GetPublicKey(data):
    file_out = open("public_rec.pem", "w")
    file_out.write(data.decode())
    file_out.close()


def DecipherMessageWithECB(data):
    print("ECB!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
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

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    data = cipher_aes.decrypt(ciphertext)
    message = unpad(data, AES.block_size).decode()
    print(message)
    messagePopUp.start(message)
    return
def DecipherMessageWithCBC(data):
    ##CBC implementation
    print("CBC!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
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

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    data = cipher_aes.decrypt(ciphertext)
    message = unpad(data, AES.block_size).decode()
    print(message)
    messagePopUp.start(message)
    return

def accept_wrapper(sock):
    conn, addr = sock.accept()
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
        recv_data = sock.recv(1024)
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
            if type == "messageECB":
                DecipherMessageWithECB(data.outb)
            if type == "messageCBC":
                DecipherMessageWithCBC(data.outb)   
            if type == "":
                if data.outb.decode() == "messageCBC":
                    type = "messageCBC"
                if data.outb.decode() == "messageECB":
                    type = "messageECB"
                if data.outb.decode() == "key":
                    type = "key"

            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]


def serverStart(host, port):
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
