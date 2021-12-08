import sqlite3,hashlib
from tkinter import *

window = Tk()

window.title("PASSWRLD")

# Function to display the screen to set master password
def displayFirstScreen():
    window.geometry("300x100")


    lbl1 = Label(window, text="Create master password ")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window, text="Confirm master password ")
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    txt2 = Entry(window, width=20, show="*")
    txt2.pack()
    txt2.focus()

    lbl3 = Label(window)
    lbl3.pack()

    # Function to save the master password
    def SetMasterPassword():
        if txt1.get() == txt2.get():
            pass
        else:
            lbl3.config(text="Passwords do not match!")

    btn = Button(window, text="Submit", command=SetMasterPassword)
    btn.pack(pady=10)

# Function to display Login Screen
def displayLoginScreen():
    window.geometry("300x200")

    lbl1 = Label(window,text="PASSWRLD")
    lbl1.pack(pady=30)

    lbl2 = Label(window, text="Enter master password")
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl3 = Label(window)
    lbl3.pack()

    # Function to check master password
    def checkPassword():
        password = "test"

        if password==txt.get():
            displayPasswordVault()
        else:
            lbl3.config(text="Incorrect Password!")
            txt.delete(0, 'end')

    btn = Button(window, text="Submit",command=checkPassword)
    btn.pack(pady=10)

# Function to display password vault
def displayPasswordVault():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("600x400")

    lbl1 = Label(window, text="PASSWRLD")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

displayFirstScreen()
displayLoginScreen()
window.mainloop()