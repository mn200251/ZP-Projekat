import hashlib
import tkinter as tk
from tkinter import messagebox
# from main import privateKeyRing, publicKeyRing
from KeyRing import *
from cryptography.hazmat.primitives.asymmetric import rsa

privateKeyRing = PrivateKeyRing()
publicKeyRing = PublicKeyRing()

class KeyGenerationGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("RSA Key Pair Generation")
        self.root.geometry("300x300")

        # Labels and Entry widgets for user inputs
        self.name_label = tk.Label(root, text="Name:")
        self.name_entry = tk.Entry(root)

        self.email_label = tk.Label(root, text="Email:")
        self.email_entry = tk.Entry(root)

        self.key_size_label = tk.Label(root, text="Key Size:")

        # Radio buttons for key size selection
        self.key_size_var = tk.IntVar()
        self.key_size_var.set(1024)  # Default key size
        self.key_size_1024 = tk.Radiobutton(root, text="1024 bits", variable=self.key_size_var, value=1024)
        self.key_size_2048 = tk.Radiobutton(root, text="2048 bits", variable=self.key_size_var, value=2048)

        self.password_label = tk.Label(root, text="Password for Private Key:")
        self.password_entry = tk.Entry(root, show="*")

        # Generate key pair button
        self.generate_button = tk.Button(root, text="Generate RSA Key Pair", command=self.generate_key_pair)

        # Pack labels, entries, radio buttons, and button
        self.name_label.pack(pady=5)
        self.name_entry.pack(pady=5)
        self.email_label.pack(pady=5)
        self.email_entry.pack(pady=5)
        self.key_size_label.pack(pady=5)
        self.key_size_1024.pack()
        self.key_size_2048.pack()
        self.password_label.pack(pady=5)
        self.password_entry.pack(pady=5)
        self.generate_button.pack(pady=10)


    def generate_key_pair(self):
        # Get user inputs
        name = self.name_entry.get()  # sta ce nam ovo ???
        email = self.email_entry.get()
        keySize = self.key_size_var.get()
        passcode = self.password_entry.get()

        if name is None or email is None or keySize is None or passcode is None:
            messagebox.showinfo("Error", "Please enter all required information")
            return

        if name == "" or email == "" or keySize is None or passcode == "":
            messagebox.showinfo("Error", "Please enter all required information")
            return

        privateKey = rsa.generate_private_key(public_exponent=65537, key_size=keySize)

        # Get the public key
        publicKey = privateKey.public_key()

        # hash the passcode
        value = passcode.encode()
        sha1_hash = hashlib.sha1()
        sha1_hash.update(value)
        hashed_value = sha1_hash.hexdigest()

        # encrypt the private key with the hashed value

        privateKeyRing.addKey(publicKey=publicKey, privateKey=privateKey, userId=email)

        # Show success message
        messagebox.showinfo("Success", "RSA Key pair generated successfully")

        self.parentWindow.refreshRings(self.parentWindow)
        self.close_window()

    def close_window(self):
        self.root.destroy()


class ApplicationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Main Application")

        # Button to open key generation GUI
        self.open_keygen_button = tk.Button(root, text="Generate RSA Key Pair", command=self.open_key_generation_gui)
        self.open_keygen_button.pack(pady=10)

    def open_key_generation_gui(self):
        # Create a new window for key generation GUI
        keygen_window = tk.Toplevel(self.root)
        keygen_app = KeyGenerationGUI(keygen_window)


def main():
    root = tk.Tk()
    app = ApplicationGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
