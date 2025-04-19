from ttkbootstrap import Style, ttk
from ttkbootstrap.constants import *
from tkinter import StringVar, Toplevel
import hashlib

def hash_message(message):
    # Hash the message using SHA-256
    hashed = hashlib.sha256(message.encode()).hexdigest()
    return hashed

def show_hash_window():
    def hash_and_display():
        message = message_var.get()
        if message:
            hashed_message = hash_message(message)
            result_label.config(text=f"SHA-256 Hash:\n{hashed_message}")
            copy_button.config(state=NORMAL)  # Enable the copy button
        else:
            result_label.config(text="Please enter a message.")
            copy_button.config(state=DISABLED)  # Disable the copy button

    def copy_to_clipboard():
        hash_value = result_label.cget("text").split("\n", 1)[1]  # Extract hash part
        root.clipboard_clear()
        root.clipboard_append(hash_value)  # Copy only the hash value
        root.update()  # Update the clipboard

    hash_window = Toplevel(root)
    hash_window.title("Hash a Message")
    hash_window.geometry("400x300")
    hash_window.resizable(False, False)

    ttk.Label(hash_window, text="Enter the message to hash:", font=("Lucida Sans typewriter", 12)).pack(pady=10)
    message_var = StringVar()
    ttk.Entry(hash_window, textvariable=message_var, font=("Arial", 12), width=40).pack(pady=5)
    ttk.Button(hash_window, text="Hash Message", command=hash_and_display, bootstyle=PRIMARY).pack(pady=10)
    result_label = ttk.Label(hash_window, text="", font=("Lucida Sans typewriter", 10), wraplength=350)
    result_label.pack(pady=10)
    copy_button = ttk.Button(hash_window, text="Copy Hash", command=copy_to_clipboard, state=DISABLED, bootstyle=SUCCESS)
    copy_button.pack(pady=10)

def show_match_window():
    def match_and_display():
        message = message_var.get()
        input_hash = hash_var.get()
        if message and input_hash:
            calculated_hash = hash_message(message)
            if calculated_hash == input_hash:
                result_label.config(text="The hash matches the message!")
            else:
                result_label.config(text="The hash does NOT match the message.")
        else:
            result_label.config(text="Please enter both a message and a hash.")

    match_window = Toplevel(root)
    match_window.title("Match a Hash")
    match_window.geometry("400x300")
    match_window.resizable(False, False)

    ttk.Label(match_window, text="Enter the message:", font=("Lucida Sans typewriter", 12)).pack(pady=10)
    message_var = StringVar()
    ttk.Entry(match_window, textvariable=message_var, font=("Arial", 12), width=40).pack(pady=5)

    ttk.Label(match_window, text="Enter the hash to match:", font=("Lucida Sans typewriter", 12)).pack(pady=10)
    hash_var = StringVar()
    ttk.Entry(match_window, textvariable=hash_var, font=("Arial", 12), width=40).pack(pady=5)

    ttk.Button(match_window, text="Match Hash", command=match_and_display, bootstyle=PRIMARY).pack(pady=10)
    result_label = ttk.Label(match_window, text="", font=("Lucida Sans typewriter", 10), wraplength=350)
    result_label.pack(pady=10)

def exit_app():
    root.destroy()

# Initialize ttkbootstrap style with a dark theme
style = Style(theme="darkly")  # Using a dark theme

root = style.master
root.title("Modern Hashing App")
root.geometry("300x250")
root.resizable(False, False)

ttk.Label(root, text="Choose an action:", font=("Lucida Sans typewriter", 14)).pack(pady=20)
ttk.Button(root, text="Hash a Message", command=show_hash_window, bootstyle=PRIMARY).pack(pady=10)
ttk.Button(root, text="Match a Hash", command=show_match_window, bootstyle=INFO).pack(pady=10)
ttk.Button(root, text="Exit", command=exit_app, bootstyle=DANGER).pack(pady=10)

root.mainloop()
