import socket
import selectors
import time
import types
import os
import sys
from tqdm import tqdm
from cipher import CipherMethods
sel = selectors.DefaultSelector()

type = ""


def GetPublicKey(data):
    file_out = open("public_rec.pem", "w")
    file_out.write(data.decode())
    file_out.close()

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
        try:
            recv_data = sock.recv(1024)
        except:
            print("")
        if recv_data:
            data.outb += recv_data
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            if type == "key":
                GetPublicKey(data.outb)
            if type == "messageECB":
                CipherMethods.DecipherMessage(data.outb, "ecb", "message")
                lsock.close()
                sel.close()
            if type == "messageCBC":
                CipherMethods.DecipherMessage(data.outb, "cbc", "message")
                lsock.close()
                sel.close()
            if type == "":
                if data.outb.decode() == "messageCBC":
                    type = "messageCBC"
                if data.outb.decode() == "messageECB":
                    type = "messageECB"
                if data.outb.decode() == "fileCBC":
                    type = "fileCBC"
                    lsock.close()
                    sel.close()
                    saveFile(data.outb, host, port, sock, "cbc")
                if data.outb.decode() == "fileECB":
                    type = "fileECB"
                    lsock.close()
                    sel.close()
                    saveFile(data.outb, host, port, sock, "ecb")
                if data.outb.decode() == "key":
                    type = "key"
            if data.outb.decode() != "fileCBC" and data.outb.decode() != "fileECB":
                sent = sock.send(data.outb)
                data.outb = data.outb[sent:]


def serverStart(host, port):
    sys.tracebacklimit = 0
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


def saveFile(data, host, port, sock, mode):
    print(data)
    """ Creating a TCP server socket """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))

    sent = sock.send(data)
    data = data[sent:]

    server.listen()
    print("[+] Listening...")

    conn, addr = server.accept()
    print(f"[+] Client connected from {addr[0]}:{addr[1]}")

    data = conn.recv(1024).decode("utf-8")
    item = data.split("__")
    FILENAME = item[0]
    FILESIZE = int(item[1])

    print("[+] Filename and filesize received from the client.")
    bar = tqdm(
        range(FILESIZE),
        f"Receiving {FILENAME}",
        unit="B",
        unit_scale=True,
        unit_divisor=1024 * 8,
    )
    size = 1024
    if mode == "ecb":
        size *= 7
    elif mode == "cbc":
        size *= 8
    with open(f"recv/{os.path.basename(FILENAME)}", "wb") as f:
        while True:
            data = conn.recv(1296 + size)
            if not data:
                break
            if mode == "ecb":
                tempText = CipherMethods.DecipherMessage(data, "ecb", "file")
            elif mode == "cbc":
                tempText = CipherMethods.DecipherMessage(data, "cbc", "file")
            f.write(tempText)
            conn.send("Data received.".encode("utf-8"))
            bar.update(1024 * 8)
    time.sleep(5)
    conn.close()
    server.close()