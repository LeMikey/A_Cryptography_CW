import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial

# Initiate database
with sqlite3.connect("PASSWRLD.db") as db:
    cursor = db.cursor()

# Creates the table to store the master password
cursor.execute("""
CREATE TABLE IF NOT EXISTS MasterPW(
id INTEGER PRIMARY KEY,
pw TEXT NOT NULL
) 
""")

# Creates the table to store the user data
cursor.execute("""
CREATE TABLE IF NOT EXISTS PWVault(
id INTEGER PRIMARY KEY,
username TEXT NOT NULL,
password TEXT NOT NULL,
description TEXT NOT NULL
) 
""")

# Function to display windows to get user input
def displayPopUp(text):
    answer = simpledialog.askstring("", text)
    return answer

# Initiate Window
window = Tk()

window.title("PASSWRLD")

# Function to implement sha512 hashing algorithm to hash the master password
def hashPW(input):
    hash = hashlib.sha512(input)
    hash = hash.hexdigest()

    return hash

# Function to display the screen to set master password (Sign Up)
def displaySignUpScreen():

    window.geometry("350x200")


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

    lbl3 = Label(window)
    lbl3.pack()

    # Function to save the master password
    def SetMasterPassword():

        if txt1.get() == txt2.get():
            # The hashed password is UTF-8 encoded
            hashedPW = hashPW(txt1.get().encode())
            insertMasterPW = """INSERT INTO MasterPW(pw)
            VALUES(?) """
            cursor.execute(insertMasterPW, [(hashedPW)])
            db.commit()

            displayPasswordVault()
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

    # Function to get hashed master password
    def getMasterPW():
        checkHashedPW = hashPW(txt.get().encode())
        cursor.execute("SELECT * FROM MasterPW where id = 1 AND pw = ?", [(checkHashedPW)])
        # print(checkHashedPW)
        return cursor.fetchall()

    # Function to check master password
    def checkPassword():
        match = getMasterPW()

        # print(match)

        if match:
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

    def addEntry():
        text1 = "Username"
        text2 = "Password"
        text3 = "Description"

        # window.withdraw()

        username = displayPopUp(text1)
        password = displayPopUp(text2)
        description = displayPopUp(text3)

        insertFields = """INSERT INTO PWVault(username, password, description)
        VALUES(?, ?, ?)"""

        cursor.execute(insertFields, (username, password, description))
        db.commit()
        displayPasswordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM PWVault WHERE id = ?", (input,))
        db.commit()

        displayPasswordVault()

    window.geometry("725x500")


    lbl1 = Label(window, text="PASSWRLD")
    lbl1.grid(column=1)

    btn = Button(window, text="Add Entry", command=addEntry)
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Description")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM PWVault")
    if(cursor.fetchall() != None):
        i=0
        while True:
            cursor.execute("SELECT * FROM PWVault")
            array = cursor.fetchall()

            lbl1 = Label(window, text=(array[i][1]))
            lbl1.grid(column=0, row=i+3)
            lbl1 = Label(window, text=(array[i][2]))
            lbl1.grid(column=1, row=i+3)
            lbl1 = Label(window, text=(array[i][3]))
            lbl1.grid(column=2, row=i+3)

            btn = Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i+3, pady=10)

            i = i+1

            cursor.execute("SELECT * FROM PWVault")
            if (len(cursor.fetchall()) <= i):
                break

cursor.execute("SELECT * FROM MasterPW")

# Displays login screen if there is a value in MasterPW if not displays the sign up screen
if cursor.fetchall():
    displayLoginScreen()
else:
    displaySignUpScreen()
window.mainloop()