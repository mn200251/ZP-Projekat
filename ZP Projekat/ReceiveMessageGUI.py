import base64
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import gzip
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives.asymmetric import rsa

class ReceiveMessageGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Receive a message")
        self.root.geometry("300x30")

        self.browse_label = tk.Label(root, text="Choose a message to decrypt:")
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_message)
        

        # Pack labels, entries, radio buttons, and button
        self.text_label.pack(pady=5)
        self.text_entry.pack(pady=5)
        self.decrypt_button.pack(pady=10)


    def browse_file(self):
        self.file_path = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select a file", filetypes=[("All files", "*.*")])


    def decrypt_message(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a message file.")
            return
        
        with open(self.file_path, "r") as file:
            text = file.read()

        # Decode the message with radix64
        radix64 = True
        if radix64:
            text = base64.b64decode(text)

        # Decrypt the message

        
        
        
        

        # Show success message
        messagebox.showinfo("Success", "Message decrypted successfully!")

        # Query the user for the destination path


        self.closeWindow()

    def closeWindow(self):
        self.root.destroy()

    @staticmethod
    def method():
        pass


class ApplicationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Main Application")

        # Button to open key generation GUI
        self.open_send_button = tk.Button(root, text="Generate RSA Key Pair", command=self.open_send_button_gui)
        self.open_send_button.pack(pady=10)

    def open_key_generation_gui(self):
        # Create a new window for key generation GUI
        send_window = tk.Toplevel(self.root)
        send_app = ReceiveMessageGUI(send_window)


def main():
    root = tk.Tk()
    app = ApplicationGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
