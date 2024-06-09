import tkinter as tk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import zipfile
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class SendMessageGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Send a message")
        self.root.geometry("300x500")

        self.text_label = tk.Label(root, text="Text message:")
        self.text_entry = tk.Entry(root)

        self.encryption_checkbox_var = tk.IntVar()
        self.authentication_checkbox_var = tk.IntVar()
        self.compress_checkbox_var = tk.IntVar()
        self.radix64_checkbox_var = tk.IntVar()

        # Checkbox entries
        self.encryption_checkbox = tk.Checkbutton(root, text="Encrypt message", variable=self.encryption_checkbox_var)
        self.authentication_checkbox = tk.Checkbutton(root, text="Authenticate message", variable=self.authentication_checkbox_var) 
        self.compress_checkbox = tk.Checkbutton(root, text="Compress message", variable=self.compress_checkbox_var)
        self.radix64_checkbox = tk.Checkbutton(root, text="Radix64 encode message", variable=self.radix64_checkbox_var)
        
        self.priv_key_label = tk.Label(root, text="Private Key index:")
        self.priv_key_entry = tk.Entry(root)

        self.publ_key_label = tk.Label(root, text="Public Key index:")
        self.publ_key_entry = tk.Entry(root)

        self.algorithm_label = tk.Label(root, text="Encryption algorithm:")

        self.algorithm_var = tk.StringVar()
        self.algorithm_var.set("Cast5")  # Default key size
        self.algorithm_cast5 = tk.Radiobutton(root, text="Cast5", variable=self.algorithm_var, value="Cast5")
        self.algorithm_aes128 = tk.Radiobutton(root, text="AES128", variable=self.algorithm_var, value="AES128")

        self.destination_label = tk.Label(root, text="Destination path:")
        self.destination_entry = tk.Entry(root)

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        

        # Pack labels, entries, radio buttons, and button
        self.text_label.pack(pady=5)
        self.text_entry.pack(pady=5)
        self.encryption_checkbox.pack()
        self.authentication_checkbox.pack()
        self.compress_checkbox.pack()
        self.radix64_checkbox.pack()
        self.priv_key_label.pack(pady=5)
        self.priv_key_entry.pack(pady=5)
        self.publ_key_label.pack(pady=5)
        self.publ_key_entry.pack(pady=5)
        self.algorithm_label.pack(pady=5)
        self.algorithm_cast5.pack()
        self.algorithm_aes128.pack()
        self.destination_label.pack(pady=5)
        self.destination_entry.pack(pady=5)
        self.send_button.pack(pady=10)

    def send_message(self):
        # Get user inputs
        text = self.text_entry.get()
        encryption = self.encryption_checkbox_var.get()
        authentication = self.authentication_checkbox_var.get()
        compress = self.compress_checkbox_var.get()
        radix64 = self.radix64_checkbox_var.get()
        priv_key_index = self.priv_key_entry.get()
        publ_key_index = self.publ_key_entry.get()
        algorithm = self.algorithm_var.get()
        destination_path = self.destination_entry.get()

        if text is None or (encryption is None and publ_key_index is None) or (authentication is None and priv_key_index is None) or destination_path is None:
            tk.messagebox.showinfo("Error", "Please enter all required information")
            return
        
        # Load private key
        if authentication:
            private_key = self.parentWindow.getPrivateKey(priv_key_index)
            
            # Hash the message with SHA-1
            digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
            digest.update(text.encode())
            hashed_message = digest.finalize()

            # Encrypt the hashed message with the private key
            signature = private_key.sign(hashed_message, padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA1())

            # Append the signature to the message
            text += signature
            print(text)

        if compress:
            # Compress the message
            compressed_message = zipfile.compress(text.encode())
            text = compressed_message

        
        # Load public key
        if encryption:
            # Generate random 128-bit session key
            session_key = os.urandom(16)

            # Encrypt the message with the session key
            if algorithm == "Cast5":
                cipher = Cipher(algorithms.CAST5(session_key), modes.CBC(os.urandom(8)), backend=default_backend())
            elif algorithm == "AES128":
                cipher = Cipher(algorithms.AES(session_key), modes.CBC(os.urandom(16)), backend=default_backend())

            public_key = self.parentWindow.getPublicKey(publ_key_index)

            # Encrypt the session key with the public key
            encrypted_session_key = public_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))

            # Append the encrypted session key to the message
            text += encrypted_session_key

        if radix64:
            # Encode the message with radix64
            text = text.encode("ascii").encode("base64")

        with open(destination_path, "w") as file:
            file.write(text)
            file.flush()
        

        # Show success message
        tk.messagebox.showinfo("Success", "Message sent successfully")

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
        send_app = SendMessageGUI(send_window)


def main():
    root = tk.Tk()
    app = ApplicationGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
