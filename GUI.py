import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'9909'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = bytes(0)


# Function to encrypt data
def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


# Function to decrypt data
def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# Initiate database
with sqlite3.connect("PASSWRLD.db") as db:
    cursor = db.cursor()

# To view .db files
# https://inloop.github.io/sqlite-viewer/

# Creates the table to store the master password
cursor.execute("""
CREATE TABLE IF NOT EXISTS MasterPW(
id INTEGER PRIMARY KEY,
pw TEXT NOT NULL,
recoveryKey TEXT NOT NULL
);
""")

# Creates the table to store the user data
cursor.execute("""
CREATE TABLE IF NOT EXISTS PWVault(
id INTEGER PRIMARY KEY,
username TEXT NOT NULL,
password TEXT NOT NULL,
description TEXT NOT NULL
); 
""")


# Function to display windows to get user input
def displayPopUp(text):
    answer = simpledialog.askstring("", text)
    return answer


# Initiate Window
window = Tk()
window.update()

window.title("PASSWRLD")

# Function to implement sha512 hashing algorithm to hash the master password
def hashPW(input):
    hash = hashlib.sha512(input)
    hash = hash.hexdigest()
    return hash


# Function to display the screen to set master password (Sign Up)
def displaySignUpScreen():
    for widget in window.winfo_children():
        widget.destroy()

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

            sql = "DELETE FROM MasterPW WHERE id = 1"
            cursor.execute(sql)

            # The hashed password is UTF-8 encoded
            hashedPW = hashPW(txt1.get().encode('utf-8'))
            # Generates random key
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPW(key.encode('utf-8'))

            # Saves encryption key
            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt1.get().encode()))

            insertMasterPW = """INSERT INTO MasterPW(pw, recoveryKey)
            VALUES(?, ?) """
            cursor.execute(insertMasterPW, ((hashedPW), (recoveryKey)))
            db.commit()

            displayRecoveryKey(key)
        else:
            lbl3.config(text="Passwords do not match!")

    btn = Button(window, text="Submit", command=SetMasterPassword)
    btn.pack(pady=10)


# Function to display Recovery Key window
def displayRecoveryKey(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x200")


    lbl1 = Label(window, text="Copy Recovery Key")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    lbl2 = Label(window, text=key)
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    # Function to copy the Recovery Key to clipboard
    def copyKey():
        pyperclip.copy(lbl2.cget("text"))

    btn = Button(window, text="Copy Key", command=copyKey)
    btn.pack(pady=10)

    # Function to close Recovery Key Window
    def done():
        displayPasswordVault()

    btn = Button(window, text="Done", command=done)
    btn.pack(pady=10)


# Function display window to reset master password
def displayResetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x200")

    lbl1 = Label(window, text="Enter Recovery Key")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl2 = Label(window)
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    # Function to return if the entered recovery key is valid
    def getRecoveryKey():
        recoveryKeyCheck = hashPW(str(txt.get()).encode('utf-8'))
        cursor.execute('SELECT * FROM MasterPW WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()

    # Function to check if recovery key is correct
    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            displaySignUpScreen()
        else:
            txt.delete(0, 'end')
            lbl2.config(text='Wrong Key')

    btn = Button(window, text="Check Key", command=checkRecoveryKey)
    btn.pack(pady=10)


# Function to display Login Screen
def displayLoginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("300x250")

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
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode('utf-8')))
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

    # Function to display window to reset master password
    def resetPassword():
        displayResetScreen()

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=10)

    btn = Button(window, text="Reset Password", command=resetPassword)
    btn.pack(pady=10)


# Function to display password vault
def displayPasswordVault():
    for widget in window.winfo_children():
        widget.destroy()

    # Function to add a new entry to the password vault
    def addEntry():
        text1 = "Username"
        text2 = "Password"
        text3 = "Description"

        # window.withdraw()

        # Data stored will be encrypted
        username = encrypt(displayPopUp(text1).encode(), encryptionKey)
        password = encrypt(displayPopUp(text2).encode(), encryptionKey)
        description = encrypt(displayPopUp(text3).encode(), encryptionKey)

        insertFields = """INSERT INTO PWVault(username, password, description)
        VALUES(?, ?, ?)"""

        cursor.execute(insertFields, (username, password, description))
        db.commit()
        displayPasswordVault()

    # Function to update entry details
    def updateEntry(input):
        updateUsername = "Enter new username"
        username = encrypt(displayPopUp(updateUsername).encode(), encryptionKey)

        updatePassword = "Enter new password"
        password = encrypt(displayPopUp(updatePassword).encode(), encryptionKey)

        cursor.execute("UPDATE PWVault SET username = ? WHERE id = ?", (username, input,))
        db.commit()
        cursor.execute("UPDATE PWVault SET password = ? WHERE id = ?", (password, input,))
        db.commit()
        displayPasswordVault()

    # Function to remove an entry from password vault
    def removeEntry(input):
        cursor.execute("DELETE FROM PWVault WHERE id = ?", (input,))
        db.commit()

        displayPasswordVault()

    # Function to copy data into clipboard
    def copyData(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    window.geometry("1000x500")

    lbl1 = Label(window, text="PASSWRLD")
    lbl1.grid(column=2)

    btn = Button(window, text="Add Entry", command=addEntry)
    btn.grid(column=2, pady=10)

    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Description")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM PWVault")
    if cursor.fetchall() is not None:
        i=0
        while True:
            cursor.execute("SELECT * FROM PWVault")
            array = cursor.fetchall()

            if len(array) == 0:
                break

            lbl1 = Label(window, text=decrypt(array[i][1], encryptionKey))
            lbl1.grid(column=0, row=i+3)
            lbl1 = Label(window, text=decrypt(array[i][2], encryptionKey))
            lbl1.grid(column=1, row=i+3)
            lbl1 = Label(window, text=decrypt(array[i][3], encryptionKey))
            lbl1.grid(column=2, row=i+3)

            btn1 = Button(window, text="Update", command=partial(updateEntry, array[i][0]))
            btn1.grid(column=3, row=i + 3, pady=10)

            username = decrypt(array[i][1], encryptionKey)
            btn2 = Button(window, text="Copy Username", command=partial(copyData, username))
            btn2.grid(column=4, row=i + 3, pady=10)

            password = decrypt(array[i][2], encryptionKey)
            btn3 = Button(window, text="Copy Password", command=partial(copyData, password))
            btn3.grid(column=5, row=i + 3, pady=10)

            btn = Button(window, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=6, row=i+3, pady=10)
            i = i+1

            cursor.execute("SELECT * FROM PWVault")
            if len(cursor.fetchall()) <= i:
                break


cursor.execute("SELECT * FROM MasterPW")

# Displays login screen if there is a value in MasterPW if not displays the sign up screen
if cursor.fetchall():
    displayLoginScreen()
else:
    displaySignUpScreen()
window.mainloop()
