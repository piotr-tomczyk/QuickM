import socket
import os
from tqdm import tqdm
from tkinter import *
import os
from cipher import CipherMethods

def clientFNC(host, port, message, type):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(type)
        data = s.recv(1024)
        s.close()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message)
        data = s.recv(1024)
        s.close()


def clientFNCFile(host, port, fileName, type, fileSize, fileNameNotCoded):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(type.encode())
        data = s.recv(1024)
        s.close()
    print(f"sent data type {data}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        SIZE = 1024 * 8
        s.connect((host, port))

        data = f"{fileName}__{fileSize}"
        s.send(data.encode("utf-8"))
        print(f"file name and file size have been sent")
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
                    s.send(CipherMethods.CipherMessage(data, "cbc"))
                else:
                    s.send(CipherMethods.CipherMessage(data, "ecb"))
                msg = s.recv(SIZE).decode("utf-8")
                bar.update(len(data))
        s.close()
    print(f"File was sent")