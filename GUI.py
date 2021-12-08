import sqlite3,hashlib
from tkinter import *

window = Tk()

window.title("PASSWRLD")

def checkPassword():
    print("Button clicked!")

#Function to display Login Screen
def loginScreen():
    window.geometry("300x200")

    lbl1 = Label(window,text="PASSWRLD")
    lbl1.pack(pady=30)

    lbl2 = Label(window, text="Enter master password")
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    txt = Entry(window,width=20)
    txt.pack()
    txt.focus()



    btn = Button(window, text="Submit",command=checkPassword)
    btn.pack(pady=10)

loginScreen()
window.mainloop()