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

from client import clientFNC
import serverFile


customtkinter.set_appearance_mode("gray")
customtkinter.set_default_color_theme("green")
class ViewHandler:
    def __init__(self, master):
        self.master = master
        master.title("QuickM")
        self.menuButtons()

    def menuButtons(self):
        server_button = customtkinter.CTkButton(
            self.master, text="Otrzymaj wiadomość", command=self.open_server
        )
        server_button.pack(pady=18)
        client_button = customtkinter.CTkButton(
            self.master, text="Wyśij wiadomość", command=self.open_client
        )
        client_button.pack(pady=18)

    def open_server(self):
        action = ServerWindow(self.open_win())
    
    def open_client(self):
        action = ClientWindow(self.open_win())

    def open_win(self):
        new_window = customtkinter.CTkToplevel(self.master)
        new_window.geometry("852x480")
        self.master.withdraw()
        return [new_window, self.master]


class ServerWindow:
    def __init__(self, master):
        self.oldWindow = master[1]
        self.master = master[0]
        self.master.title("QuickM - server")
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.menuButtons()
    def menuButtons(self):
        self.ip_label = customtkinter.CTkLabel(master=self.master,width=120,height=25,text="IP:")
        self.ip_label.pack(pady=18)
        self.ip_entry = customtkinter.CTkEntry(master=self.master,
                               width=120,
                               height=25,
                               corner_radius=10)
        self.ip_entry.insert(-1, '127.0.0.1')
        self.ip_entry.pack(pady=18)
        self.port_label = customtkinter.CTkLabel(master=self.master,width=120,height=25,text="Port:")
        self.port_label.pack()
        self.port_entry = customtkinter.CTkEntry(master=self.master,
                               width=120,
                               height=25,
                               corner_radius=10)
        self.port_entry.pack(pady=18)

        server_button = customtkinter.CTkButton(
            self.master, text="Odpal Server", command=self.serverInit
        )
        server_button.pack(pady=18)

    def serverInit(self):
        data = GetPublicKey()
        clientThread = multiprocessing.Process(
            target=clientFNC,
            args=(
                self.ip_entry.get(),
                int(self.port_entry.get()),
                data,
                "key".encode()
            ),
        )
        clientThread.start()
        sleep(5)
        clientThread.terminate()
        
        serverThread = multiprocessing.Process(
            target=serverFile.serverStart,
            args=(
                self.ip_entry.get(),
                int(self.port_entry.get()),
            ),
        )
        serverThread.start()
        sleep(5)
        serverThread.terminate()

    def on_closing(self):
        self.oldWindow.destroy()

class ClientWindow:
    def __init__(self, master):
        self.oldWindow = master[1]
        self.master = master[0]
        self.master.title("QuickM - client")
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.menuButtons()

    def menuButtons(self):
        self.ip_label = customtkinter.CTkLabel(master=self.master,width=120,height=25,text="IP:")
        self.ip_label.pack(pady=18)
        self.ip_entry = customtkinter.CTkEntry(master=self.master,
                               width=120,
                               height=25,
                               corner_radius=10)
        self.ip_entry.insert(-1, '127.0.0.1')
        self.ip_entry.pack(pady=18)
        self.port_label = customtkinter.CTkLabel(master=self.master,width=120,height=25,text="Port:")
        self.port_label.pack()
        self.port_entry = customtkinter.CTkEntry(master=self.master,
                               width=120,
                               height=25,
                               corner_radius=10)
        self.port_entry.pack(pady=18)

        self.message_label = customtkinter.CTkLabel(master=self.master,width=120,height=25,text="Message:")
        self.message_label.pack()
        
        self.message_entry = customtkinter.CTkEntry(master=self.master,
                               width=120,
                               height=25,
                               corner_radius=10)
        self.message_entry.pack(pady=18)

        self.is_ecb = tkinter.IntVar(self.master, 0)

        self.ecb_button = customtkinter.CTkRadioButton(master=self.master, text="ECB",variable= self.is_ecb, value=0);
        self.ecb_button.pack()

        self.ecb_button = customtkinter.CTkRadioButton(master=self.master, text="CBC",variable= self.is_ecb, value=1);
        self.ecb_button.pack()

        self.send_button = customtkinter.CTkButton(
            self.master, text="Wyślij wiadomość", command=self.clientInit
        )
        self.send_button.pack(pady=18)

    def clientInit(self):
        if self.is_ecb.get() == 0:
            print("selected ECB")
        if self.is_ecb.get() == 1:
            print("selected: CBC")
        serverThread = multiprocessing.Process(
            target=serverFile.serverStart,
            args=(
                self.ip_entry.get(),
                int(self.port_entry.get()),
            ),
        )
        serverThread.start()
        sleep(5)
        serverThread.terminate()
        sleep(2)
        messageType = "messageECB"
        if self.is_ecb.get() == 0:
            data = CipherMessageWithECB(self.message_entry.get())
            messageType = "messageECB"
        if self.is_ecb.get() == 1:
            data = CipherMessageWithCBC(self.message_entry.get())
            messageType = "messageCBC"
        clientThread = multiprocessing.Process(
            target=clientFNC,
            args=(
                self.ip_entry.get(),
                int(self.port_entry.get()),
                data,
                messageType.encode()
            ),
        )
        clientThread.start()
        sleep(5)
        clientThread.terminate()
        
    def on_closing(self):
        self.oldWindow.destroy()

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

def GetPublicKey():
    return str(open("RSApub/public.pem").read()).encode()

def CipherMessageWithECB(data):
    data = pad(data.encode(), AES.block_size)
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("public_rec.pem").read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    ciphertext = cipher_aes.encrypt(data)

    text = enc_session_key + ciphertext
    [file_out.write(x) for x in (enc_session_key, ciphertext)]
    file_out.close()
    
    return text

def CipherMessageWithCBC(data):
    #CBC CODE
    data = pad(data.encode(), AES.block_size)
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("public_rec.pem").read())
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    ciphertext = cipher_aes.encrypt(data)

    text = enc_session_key + ciphertext
    [file_out.write(x) for x in (enc_session_key, ciphertext)]
    file_out.close()
    
    return text

def main():
    if not(os.path.exists('RSApriv')):
        GenerateRSAKeys()
    root = customtkinter.CTk()
    root.geometry("852x480")
    my_gui = ViewHandler(root)
    root.mainloop()


if __name__ == "__main__":
    main()