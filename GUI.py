import sqlite3
window.title("PASSWRLD")
# Database Part
with sqlite3.connect("vault.db")as database:
    cursor = database.cursor() # creating the DB

cursor.execute(""" 
CREATE TABLE IF NOT EXIST mainpass(    
userName  INTEGER PRIMARY KEY,
password TEXT NOT NULL)
""" ) # Creating a table in DB





#Function to display Login Screen
# Function to display the screen to set master password
def displayFirstScreen(geometry=window.geometry("300x100")):
    geometry


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
            hashedPW = txt.get

            enteredPassword="""INSERT INTO mainpass(password) 
            VALUES(?)"""
            cursor.execute(enteredPassword, [(hashedPW)])
            database.commit()

            displayPasswordVault()
            pass
        else:
            lbl3.config(text="Passwords do not match!")

    btn = Button(window, text="Submit", command=SetMasterPassword)
    btn.pack(pady=10)

# Function to display Login Screen
def displayLoginScreen():
    window.geometry("300x200")

@@ -23,27 +57,29 @@ def displayLoginScreen():
    lbl3 = Label(window)
    lbl3.pack()

    #Function to check master password
    # Function to check master password

    def getMainPW():
        checkHashedPW = txt.get()
        cursor.execute("SELECT * FROM mainpass WHERE userName = 1 AND password =?", [(checkHashedPW)])
        return cursor.fetchall()


    def checkPassword():
        match = "test"

        if match :
            displayPasswordVault()
        else:
            lbl3.config(text="Incorrect Password!")
            txt.delete(0, 'end')

    btn = Button(window, text="Submit",command=checkPassword)
    btn.pack(pady=10)

#Function to display password vault
# Function to display password vault
def displayPasswordVault():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("600x400")

    lbl1 = Label(window, text="Password Vault")
    lbl1 = Label(window, text="PASSWRLD")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

cursor.execute("SELECT * FROM mainpass")
if cursor.fetchall():
    displayLoginScreen()
else:
    displayFirstScreen()
window.mainloop()