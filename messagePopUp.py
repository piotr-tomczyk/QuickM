from tkinter import *
import customtkinter


class ViewHandler:
    def __init__(self, master, message):
        self.master = master
        self.message = message
        master.title("QuickM")
        self.showMessage()

    def showMessage(self):
        self.ip_label = customtkinter.CTkLabel(
            master=self.master, width=120, height=25, text="Wiadomość: " + self.message
        )
        self.ip_label.pack(pady=18)


def start(message):
    root = customtkinter.CTk()
    root.geometry("400x240")
    my_gui = ViewHandler(root, message)
    root.mainloop()



