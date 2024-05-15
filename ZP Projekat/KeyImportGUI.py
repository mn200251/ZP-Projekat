import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from KeyGenerationGUI import privateKeyRing, publicKeyRing

class KeyImportGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Public Key Importer")
        self.root.geometry("400x300")

        self.file_path = ""
        self.owner_trust = ""
        self.user_id = ""
        self.signature_trusts = ""

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.root, text="Select Public Key File (.pem):").pack(pady=10)

        # .file_entry = ttk.Entry(self.root, width=40)
        # self.file_entry.pack(pady=5)

        ttk.Button(self.root, text="Browse", command=self.browse_file).pack(pady=5)

        ttk.Label(self.root, text="Owner Trust (0-100):").pack(pady=5)
        self.owner_trust_entry = ttk.Entry(self.root, width=40)
        self.owner_trust_entry.pack(pady=5)

        ttk.Label(self.root, text="User ID:").pack(pady=5)
        self.user_id_entry = ttk.Entry(self.root, width=40)
        self.user_id_entry.pack(pady=5)

        ttk.Label(self.root, text="Signature Trusts (optional):").pack(pady=5)
        self.signature_trusts_entry = ttk.Entry(self.root, width=40)
        self.signature_trusts_entry.pack(pady=5)

        ttk.Button(self.root, text="Import Public Key", command=self.import_public_key).pack(pady=10)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
        # self.file_entry.delete(0, tk.END)
        # self.file_entry.insert(0, self.file_path)

    def import_public_key(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a public key file.")
            return

        self.owner_trust = int(self.owner_trust_entry.get())
        self.user_id = self.user_id_entry.get()
        self.signature_trusts = self.signature_trusts_entry.get()

        if self.owner_trust is None or self.user_id is None:
            messagebox.showerror("Error", "Please fill in all fields!")

        if self.owner_trust == "" or self.user_id == "":
            messagebox.showerror("Error", "Please fill in all required fields!")

        if type(self.owner_trust) is not int:
            messagebox.showerror("Error", "Owner Trust must be a number!")

        # check if signatures are valid


        # Read the public key from the selected file
        with open(self.file_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())

        # Further process the public key and additional information as needed
        # For example, you can store them in a data structure or perform other operations

        # # Reset the fields
        # # self.file_entry.delete(0, tk.END)
        # self.owner_trust_entry.delete(0, tk.END)
        # self.user_id_entry.delete(0, tk.END)
        # self.signature_trusts_entry.delete(0, tk.END)
        # self.file_path = ""
        # self.owner_trust = ""
        # self.user_id = ""
        # self.signature_trusts = ""
        publicKeyRing.addKey(public_key, self.owner_trust, self.user_id, self.signature_trusts)

        self.parentWindow.refreshRings(self.parentWindow)
        self.closeWindow()

    def closeWindow(self):
        self.root.destroy()
