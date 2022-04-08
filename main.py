from base64 import b64decode, b64encode
from tkinter import *

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

        send_button = customtkinter.CTkButton(
            self.master, text="Wyślij wiadomość", command=self.clientInit
        )
        send_button.pack(pady=18)

    def clientInit(self):
        clientThread = multiprocessing.Process(
            target=clientFNC,
            args=(
                self.ip_entry.get(),
                int(self.port_entry.get()),
                self.message_entry.get(),
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


# def pad_message(message):
#   while len(message) % 16 != 0:
#     message = message + " "
#   return message


def CipherMessageWithECB():
    data = "I met aliens in UFO. Here is the map."
    data = pad(data.encode("utf-8"), AES.block_size)
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("RSApub/public.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    ciphertext = cipher_aes.encrypt(data)
    [file_out.write(x) for x in (enc_session_key, ciphertext)]
    file_out.close()


def DecipherMessageWithECB():
    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("RSApriv/private.pem").read())

    enc_session_key, ciphertext = [
        file_in.read(x) for x in (private_key.size_in_bytes(), -1)
    ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_ECB)
    data = cipher_aes.decrypt(ciphertext)
    print(data.decode("utf-8"))


def Test():
    data = "I met aliens in UFO. Here is the map."
    data = pad(data.encode("utf-8"), AES.block_size)
    file_out = open("encrypted_data.bin", "wb")

    recipient_key = RSA.import_key(open("RSApub/public.pem").read())
    session_key = get_random_bytes(AES.block_size)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(cipher_rsa, AES.MODE_CBC, session_key)
    ciphertext = cipher_aes.encrypt(data, AES.block_size)
    [
        file_out.write(x)
        for x in (enc_session_key, b64encode(enc_session_key + ciphertext))
    ]
    file_out.close()
    # def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC):
    # IV = "A"*16  #We'll manually set the initialization vector to simplify things
    # aes = AES.new(key, mode, IV)
    # new_data = aes.encrypt(data)
    # return new_data


def detest():
    file_in = open("encrypted_data.bin", "rb")

    private_key = RSA.import_key(open("RSApriv/private.pem").read())

    enc_session_key, ciphertext = [
        file_in.read(x) for x in (private_key.size_in_bytes(), -1)
    ]

    raw = b64decode(ciphertext)

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_CBC, raw[: AES.block_size])
    data = unpad(cipher_aes.decrypt(raw[: AES.block_size]), AES.block_size)
    print(data)


def main():
    # if not(os.path.exists('RSApriv')):
    #     GenerateRSAKeys()
    # Test()
    # detest()
    root = customtkinter.CTk()
    root.geometry("852x480")
    my_gui = ViewHandler(root)
    root.mainloop()


if __name__ == "__main__":
    main()
