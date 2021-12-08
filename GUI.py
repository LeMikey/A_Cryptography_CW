import sqlite3,hashlib
from tkinter import *

window = Tk()

window.title("PASSWRLD")

#Function to display Login Screen
def loginScreen():
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

    #Function to check master password
    def checkPassword():
        password = "test"

        if password==txt.get():
            print("Correct Answer!")
        else:
            lbl3.config(text="Incorrect Password!")

    btn = Button(window, text="Submit",command=checkPassword)
    btn.pack(pady=10)

#Function to display password vault


loginScreen()
window.mainloop()