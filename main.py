from tkinter import *
import tkinter
import os
import customtkinter
from time import sleep
import multiprocessing
from tkinter.filedialog import askopenfilename

from client import clientFNC, clientFNCFile
import serverFile

from cipher import CipherMethods

customtkinter.set_appearance_mode("gray")
customtkinter.set_default_color_theme("green")

fileSize = 0


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

        client_file_button = customtkinter.CTkButton(
            self.master, text="Wyśij plik", command=self.open_client_file
        )
        client_file_button.pack(pady=18)

    def open_server(self):
        action = ServerWindow(self.open_win())

    def open_client(self):
        action = ClientWindow(self.open_win())

    def open_client_file(self):
        action = ClientFileWindow(self.open_win())

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
        self.ip_label = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="IP:"
        )
        self.ip_label.pack(pady=18)
        self.ip_entry = customtkinter.CTkEntry(
            master=self.master, width=120, height=25, corner_radius=10
        )
        self.ip_entry.insert(-1, "127.0.0.1")
        self.ip_entry.pack(pady=18)
        self.port_label = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="Port:"
        )
        self.port_label.pack()
        self.port_entry = customtkinter.CTkEntry(
            master=self.master, width=120, height=25, corner_radius=10
        )
        self.port_entry.insert(-1, "5000")
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
                "key".encode(),
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
        # sleep(50)
        # serverThread.terminate()

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
        self.ip_label = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="IP:"
        )
        self.ip_label.pack(pady=18)
        self.ip_entry = customtkinter.CTkEntry(
            master=self.master, width=120, height=25, corner_radius=10
        )
        self.ip_entry.insert(-1, "127.0.0.1")
        self.ip_entry.pack(pady=18)
        self.port_label = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="Port:"
        )
        self.port_label.pack()
        self.port_entry = customtkinter.CTkEntry(
            master=self.master, width=120, height=25, corner_radius=10
        )
        self.port_entry.insert(-1, "5000")
        self.port_entry.pack(pady=18)

        self.message_label = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="Message:"
        )
        self.message_label.pack()

        self.message_entry = customtkinter.CTkEntry(
            master=self.master, width=120, height=25, corner_radius=10
        )
        self.message_entry.pack(pady=18)

        self.is_ecb = tkinter.IntVar(self.master, 0)

        self.ecb_button = customtkinter.CTkRadioButton(
            master=self.master, text="ECB", variable=self.is_ecb, value=0
        )
        self.ecb_button.pack()

        self.ecb_button = customtkinter.CTkRadioButton(
            master=self.master, text="CBC", variable=self.is_ecb, value=1
        )
        self.ecb_button.pack()

        self.send_button = customtkinter.CTkButton(
            self.master, text="Wyślij wiadomość", command=self.clientInit
        )
        self.send_button.pack(pady=18)

    def clientInit(self):
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
        sleep(4)
        messageType = "messageECB"
        if self.is_ecb.get() == 0:
            data = CipherMethods.CipherMessage(repr(self.message_entry.get()).encode(), "ecb")
            messageType = "messageECB"
        if self.is_ecb.get() == 1:
            data = CipherMethods.CipherMessage(repr(self.message_entry.get()).encode(), "cbc")
            messageType = "messageCBC"
        clientThread = multiprocessing.Process(
            target=clientFNC,
            args=(
                self.ip_entry.get(),
                int(self.port_entry.get()),
                data,
                messageType.encode(),
            ),
        )
        clientThread.start()

    def on_closing(self):
        self.oldWindow.destroy()


class ClientFileWindow:
    def __init__(self, master):
        self.oldWindow = master[1]
        self.master = master[0]
        self.master.title("QuickM - file_client")
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.menuButtons()

    def menuButtons(self):
        self.ip_label = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="IP:"
        )
        self.ip_label.pack(pady=18)
        self.ip_entry = customtkinter.CTkEntry(
            master=self.master, width=120, height=25, corner_radius=10
        )
        self.ip_entry.insert(-1, "127.0.0.1")
        self.ip_entry.pack(pady=18)
        self.port_label = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="Port:"
        )
        self.port_label.pack()
        self.port_entry = customtkinter.CTkEntry(
            master=self.master, width=120, height=25, corner_radius=10
        )
        self.port_entry.insert(-1, "5000")
        self.port_entry.pack(pady=18)

        self.message_label_1 = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="Plik:"
        )
        self.message_label_1.pack()

        self.message_label_2 = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="WYBÓR PLIKU"
        )
        self.message_label_2.pack()

        self.filename = ""

        self.choose_button = customtkinter.CTkButton(
            self.master, text="Wybierz Plik", command=self.chooseFile
        )
        self.choose_button.pack(pady=18)

        self.message_file_label = customtkinter.CTkLabel(
            master=self.master,
            width=120,
            height=25,
            text="WYBRANY PLIK: " + self.filename,
        )
        self.message_file_label.pack()

        self.is_ecb = tkinter.IntVar(self.master, 0)

        self.ecb_button = customtkinter.CTkRadioButton(
            master=self.master, text="ECB", variable=self.is_ecb, value=0
        )
        self.ecb_button.pack()

        self.ecb_button = customtkinter.CTkRadioButton(
            master=self.master, text="CBC", variable=self.is_ecb, value=1
        )
        self.ecb_button.pack()

        self.send_button = customtkinter.CTkButton(
            self.master, text="Wyślij plik", command=self.clientInit
        )
        self.send_button.pack(pady=18)

    def clientInit(self):
        global fileSize
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
        sleep(4)
        messageType = "fileECB"
        if self.is_ecb.get() == 0:
            messageType = "fileECB"
        if self.is_ecb.get() == 1:
            messageType = "fileCBC"
        data = self.filename
        fileSize = os.path.getsize(self.filename)
        clientThread = multiprocessing.Process(
            target=clientFNCFile,
            args=(
                self.ip_entry.get(),
                int(self.port_entry.get()),
                data,
                messageType,
                fileSize,
                self.filename,
            ),
        )
        clientThread.start()

    def chooseFile(self):
        self.filename = askopenfilename()
        self.message_file_label["text"] = "WYBRANY PLIK: " + self.filename
        return

    def on_closing(self):
        self.oldWindow.destroy()

def GetPublicKey():
    return str(open("RSApub/public.pem").read()).encode()

def main():
    if not (os.path.exists("RSApriv")):
        CipherMethods.GenerateRSAKeys()
    if not (os.path.exists("recv")):
        os.mkdir("recv")
    root = customtkinter.CTk()
    root.geometry("852x480")
    my_gui = ViewHandler(root)
    root.mainloop()


if __name__ == "__main__":
    main()
