from tkinter import Tk
import sqlite3
# Initiate database
# Referred from: https://docs.python.org/3/library/sqlite3.html

with sqlite3.connect("PASSWRLD.db") as db:
    cursor = db.cursor()

# To view .db files
# https://inloop.github.io/sqlite-viewer/

# Creates the table to store the master password
cursor.execute("""
CREATE TABLE IF NOT EXISTS MasterPW(
id INTEGER PRIMARY KEY,
pw TEXT NOT NULL
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

# Initiate Window
window = Tk()
window.update()

window.title("PASSWRLD")