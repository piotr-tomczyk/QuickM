import socket
import selectors
import time
import types
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os
from Crypto.Util.Padding import unpad, pad
import messagePopUp
from tqdm import tqdm
import ast
from secrets import token_bytes

sel = selectors.DefaultSelector()

type = ""


def GetPublicKey(data):
    file_out = open("public_rec.pem", "w")
    file_out.write(data.decode())
    file_out.close()


def DecipherMessageWithECB(data):
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
    messagePopUp.start(message)
    return


def DecipherMessageWithCBC(data):
    ##CBC implementation
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

    cipher_aes = AES.new(session_key[0:16], AES.MODE_CBC, session_key[16:32])
    data = cipher_aes.decrypt(ciphertext)
    message = unpad(data, AES.block_size).decode()
    messagePopUp.start(message)
    return


def DecipherFileWithECB(data):
    file_out = open("encrypted_data1.bin", "wb")
    file_out.write(data)
    file_out.close()
    file_in = open("encrypted_data1.bin", "rb")
    private_key = RSA.import_key(open("RSApriv/private.pem").read())
    enc_session_key, ciphertext = [
        file_in.read(x) for x in (private_key.size_in_bytes(), -1)
    ]

    file_in.close()
    os.remove("encrypted_data1.bin")

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    data = cipher_aes.decrypt(ciphertext)
    # AES.block_size
    message = data[:1024]

    return message


def DecipherFileWithCBC(data):
    file_out = open("encrypted_data1.bin", "wb")
    file_out.write(data)
    file_out.close()
    file_in = open("encrypted_data1.bin", "rb")
    private_key = RSA.import_key(open("RSApriv/private.pem").read())
    enc_session_key, ciphertext = [
        file_in.read(x) for x in (private_key.size_in_bytes(), -1)
    ]

    file_in.close()
    os.remove("encrypted_data1.bin")

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key[0:16], AES.MODE_CBC, session_key[16:32])
    data = cipher_aes.decrypt(ciphertext)
    # AES.block_size
    message = data[:1024]

    return message


def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)


def service_connection(key, mask, host, port, lsock, sel):
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
                if data.outb.decode() == "fileCBC":
                    type = "fileCBC"
                    lsock.close()
                    sel.close()
                    saveCBCFile(data.outb, host, port, sock)
                if data.outb.decode() == "fileECB":
                    type = "fileECB"
                    lsock.close()
                    sel.close()
                    saveECBFile(data.outb, host, port, sock)
                if data.outb.decode() == "key":
                    type = "key"
            if data.outb.decode() != "fileCBC" and data.outb.decode() != "fileECB":
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]


def serverStart(host, port):
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind((host, port))
    lsock.listen()
    print(f"[+] Listening on {(host, port)}")
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)

    try:
        while True:
            events = sel.select(timeout=None)
            for key, mask in events:
                if key.data is None:
                    accept_wrapper(key.fileobj)
                else:
                    service_connection(key, mask, host, port, lsock, sel)
    except KeyboardInterrupt:
        print("Caught keyboard interrupt, exiting")
    finally:
        sel.close()


def saveECBFile(data, host, port, sock):
    print("hereECB")
    print("\n=================\n")
    print(data)
    """ Creating a TCP server socket """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))

    sent = sock.send(data)
    data = data[sent:]

    server.listen()
    print("[+] Listening...")

    """ Accepting the connection from the client. """
    conn, addr = server.accept()
    print(conn)
    print(addr)
    print(f"[+] Client connected from {addr[0]}:{addr[1]}")

    """ Receiving the filename and filesize from the client. """
    data = conn.recv(1024).decode("utf-8")
    item = data.split("__")
    FILENAME = item[0]
    FILESIZE = int(item[1])
    print(FILENAME)
    print(FILESIZE)

    print("[+] Filename and filesize received from the client.")
    print("sleeper")
    """ Data transfer """
    bar = tqdm(
        range(FILESIZE),
        f"Receiving {FILENAME}",
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
    )
    with open(f"recv_{os.path.basename(FILENAME)}", "wb") as f:
        tempVar = True
        while tempVar:
            # if tempFilesize < 0:
            #    break
            data = conn.recv(1296)
            if not data:
                break
            tempText = DecipherFileWithECB(data)
            f.write(tempText)
            # f.write(data)
            conn.send("Data received.".encode("utf-8"))
            # print(len(tempText))
            bar.update(1024)

    """ Closing connection. """
    time.sleep(5)
    conn.close()
    server.close()
    print("\n=================\n")


def saveCBCFile(data, host, port, sock):
    print("hereCBC")
    print("\n=================\n")
    print(data)
    """ Creating a TCP server socket """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))

    sent = sock.send(data)
    data = data[sent:]

    server.listen()
    print("[+] Listening...")

    """ Accepting the connection from the client. """
    conn, addr = server.accept()
    print(conn)
    print(addr)
    print(f"[+] Client connected from {addr[0]}:{addr[1]}")

    """ Receiving the filename and filesize from the client. """
    data = conn.recv(1024).decode("utf-8")
    item = data.split("__")
    FILENAME = item[0]
    FILESIZE = int(item[1])
    print(FILENAME)
    print(FILESIZE)

    print("[+] Filename and filesize received from the client.")
    print("sleeper")
    """ Data transfer """
    bar = tqdm(
        range(FILESIZE),
        f"Receiving {FILENAME}",
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
    )
    with open(f"recv_{os.path.basename(FILENAME)}", "wb") as f:
        tempVar = True
        while tempVar:
            # if tempFilesize < 0:
            #    break
            data = conn.recv(1296)
            if not data:
                break
            tempText = DecipherFileWithCBC(data)
            f.write(tempText)
            # f.write(data)
            conn.send("Data received.".encode("utf-8"))
            # print(len(tempText))
            bar.update(1024)

    """ Closing connection. """
    time.sleep(5)
    conn.close()
    server.close()
    print("\n=================\n")
