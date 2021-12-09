import sqlite3,hashlib
from tkinter import *

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
    txt2.focus()

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
    window.geometry("600x400")

    lbl1 = Label(window, text="PASSWRLD")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

cursor.execute("SELECT * FROM MasterPW")

# Displays login screen if there is a value in MasterPW if not displays the sign up screen
if cursor.fetchall():
    displayLoginScreen()
else:
    displaySignUpScreen()
window.mainloop()