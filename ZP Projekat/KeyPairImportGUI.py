import os
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox
from tkinter import filedialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from KeyGenerationGUI import privateKeyRing, publicKeyRing

class KeyPairImportGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Public Key Importer")
        self.root.geometry("400x300")

        self.file_path = ""
        self.user_id = ""

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.root, text="Select Public Key File (.pem):").pack(pady=10)

        # .file_entry = ttk.Entry(self.root, width=40)
        # self.file_entry.pack(pady=5)

        ttk.Button(self.root, text="Browse", command=self.browse_file).pack(pady=5)

        ttk.Label(self.root, text="User ID:").pack(pady=5)
        self.user_id_entry = ttk.Entry(self.root, width=40)
        self.user_id_entry.pack(pady=5)

        ttk.Button(self.root, text="Import Public Key", command=self.importPairFromPEM).pack(pady=10)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        # self.file_entry.delete(0, tk.END)
        # self.file_entry.insert(0, self.file_path)


    def importPairFromPEM(self, password=None):
        if self.user_id_entry.get() == "" or self.user_id_entry.get() is None:
            messagebox.showerror("Error", "Name cannot be empty!")
            return

        if not self.file_path:
            messagebox.showerror("Error", "Please select a key pair file.")
            return

        currentDirectory = os.getcwd()

        # Read the PEM-formatted bytes from the file
        with open(self.file_path, "rb") as f:
            pem_data = f.read()

            # Separate the public key and encrypted private key
            public_key = None
            private_key = None

            try:
                # Split the pem_data into parts
                pem_parts = pem_data.split(b'-----END PUBLIC KEY-----')
                public_key_pem = pem_parts[0] + b'-----END PUBLIC KEY-----'
                private_key_pem = pem_parts[1].strip()

                # Load the public key
                public_key = serialization.load_pem_public_key(
                    public_key_pem,
                    backend=default_backend()
                )

                # Load the private key
                private_key = private_key_pem

                if privateKeyRing.loadKey(datetime.now(), public_key, private_key, self.user_id_entry.get()):
                    self.parentWindow.refreshRings()

                    messagebox.showinfo("Success", "Successfully imported key pair from PEM file.")

                else:
                    messagebox.showwarning("Warning", "Key pair is already imported!")

            except Exception as e:
                messagebox.showerror("Error loading key pair!", str(e))

        self.closeWindow()



    def closeWindow(self):
        self.root.destroy()
