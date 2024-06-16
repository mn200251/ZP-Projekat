import os
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from KeyGenerationGUI import privateKeyRing, publicKeyRing

class KeyPairExportGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Export Key Pair")
        self.root.geometry("250x125")

        nameLabel = ttk.Label(self.root, text="Name of .pem file: ")
        self.name = tk.Entry(root)

        # Radio buttons for selecting key ring
        # self.keyRingType = tk.IntVar()
        # self.keyRingType.set(1)  # Default value
        # private_key_ring_radio = tk.Radiobutton(root, text="Private Key Ring", variable=self.keyRingType, value=1)
        # public_key_ring_radio = tk.Radiobutton(root, text="Public Key Ring", variable=self.keyRingType, value=2)


        # Entry for typing row index
        indexLabel = ttk.Label(self.root, text="Index: ")
        self.index = tk.Entry(root)

        # Button to export public key
        export_button = tk.Button(root, text="Export Public Key", command=self.exportKeyPair)

        # Layout
        nameLabel.pack()
        self.name.pack()
        # private_key_ring_radio.pack()
        # public_key_ring_radio.pack()
        indexLabel.pack()
        self.index.pack()
        export_button.pack()

    def exportKeyPair(self):
        # print(self.name.get())
        if self.name.get() == "" or self.name.get() is None:
            messagebox.showerror("Error", "Name cannot be empty!")
            return
        if self.index == "" or self.index is None:
            messagebox.showerror("Error", "Index cannot be empty!")
            return

        allKeys = privateKeyRing.getAllKeys()

        try:
            targetRow = allKeys[int(self.index.get())]
        except ValueError:
            messagebox.showerror("Error", "Index cannot be empty!")
            return
        except TypeError:
            messagebox.showerror(title="Error", message="Index must be an integer!")
            return
        except IndexError:
            messagebox.showerror("Error", "Index out of range!")
            return

        KeyPairExportGUI.exportPair2PEM(targetRow.publicKey, targetRow.encryptedPrivateKey, self.name.get())
        messagebox.showinfo("Success", "Public key exported successfully!")
        self.closeWindow()

    @staticmethod
    def exportPair2PEM(public_key, encryptedPrivateKey, output_file):
        # Serialize the public key to bytes in PEM format
        pem_public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        pem_private_bytes = encryptedPrivateKey

        currentDirectory = os.getcwd()
        path = os.path.join(currentDirectory, "Key Pairs", output_file + ".pem")

        os.makedirs(os.path.dirname(path), exist_ok=True)

        # Write the PEM-formatted bytes to a file
        with open(path, "wb") as f:
            f.write(pem_public_bytes)
            f.write(b"\n")
            f.write(pem_private_bytes)

        print(f"Keys exported to: {path}")

    def closeWindow(self):
        self.root.destroy()