import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import hashlib
import random
import string
import uuid
import pandas as pd
from datetime import datetime
import pyperclip

def generate_password(website, date_time, length=16):
    mac_address = hex(uuid.getnode())[2:]
    unique_string = f"{mac_address}_{website}_{date_time}"
    hashed_value = hashlib.sha256(unique_string.encode()).hexdigest()
    random.seed(hashed_value)
    password_chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choices(password_chars, k=length))
    
    save_to_csv(website, date_time)
    return password

def save_to_csv(website, date_time):
    data = {'Website': [website], 'Date-Time': [date_time]}
    df = pd.DataFrame(data)
    try:
        df_existing = pd.read_csv("password_data.csv")
        df_existing = pd.concat([df_existing, df], ignore_index=True)
        df_existing.to_csv("password_data.csv", index=False)
    except FileNotFoundError:
        df.to_csv("password_data.csv", index=False)

def show_password():
    website = website_entry.get()
    date_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    password = generate_password(website, date_time)
    password_var.set(password)

def toggle_password():
    if password_entry.cget('show') == "*":
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

def copy_to_clipboard():
    pyperclip.copy(password_var.get())
    messagebox.showinfo("Copied", "Password copied to clipboard!")

# GUI Setup
root = tk.Tk()
root.title("SecureMACPassGen")
root.geometry("400x300")

# Website Entry
website_label = tk.Label(root, text="Website:")
website_label.pack()
website_entry = tk.Entry(root)
website_entry.pack()

# Password Entry (Hidden by Default)
password_var = tk.StringVar()
password_label = tk.Label(root, text="Generated Password:")
password_label.pack()
password_entry = tk.Entry(root, textvariable=password_var, show="*")
password_entry.pack()

# Buttons
generate_button = tk.Button(root, text="Generate Password", command=show_password)
generate_button.pack()

show_button = tk.Button(root, text="Show/Hide", command=toggle_password)
show_button.pack()

copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack()

root.mainloop()