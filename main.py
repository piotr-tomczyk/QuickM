from doctest import master
from tkinter import *
from tkinter import Tk, Label, Button,ttk
from typing import List

class User:
    def __init__(self, name:str):
        self.name:str = name

class UserHandler:
    def __init__(self):
        self.listOfUsers:List[User] = []

    def addUser(self, user:User):
        self.listOfUsers.append(user)

class ViewHandler:
    def __init__(self, master):
        self.master = master
        master.title("QuickM")

    def addLabels(self, userlist):
        for user in userlist:
            self.label = Label(self.master, text=user.name)
            self.label.pack()
            
            self.greet_button = Button(self.master, text="Greet", command=lambda user = user: self.greet(user))
            self.greet_button.pack()

        #ttk.Button(self.master, text="Open", command=self.open_win).pack()


    def greet(self, user):
        self.open_win()
        action = ActionWindow(self.master, user)
        action.addLabels()

    def open_win(self):
        self.master.destroy()
        self.master = Tk()
        self.master.geometry("852x480")
    

class ActionWindow:
    def __init__(self, master, user:User):
        self.master = master
        master.title("QuickM")
        self.user = user

    def napisz(self):
        print("XD")

    def addLabels(self):
        self.label = Label(self.master, text=self.user.name)
        self.label.pack()
        Button(self.master, text="Open", command=self.napisz).pack()

root = Tk()
root.geometry('852x480')
userHandler = UserHandler()
for i in range (5):
    userHandler.addUser(User(str(i)))
my_gui = ViewHandler(root)
my_gui.addLabels(userHandler.listOfUsers)
root.mainloop()