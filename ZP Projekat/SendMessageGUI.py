import base64
import json
import tkinter as tk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import utils

from cryptography.hazmat.primitives.asymmetric import rsa

class SendMessageGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Send a message")
        self.root.geometry("300x550")

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
        
        self.priv_key_label = tk.Label(root, text="Private Key userId:")
        self.priv_key_entry = tk.Entry(root)

        self.priv_key_pass = tk.Label(root, text="Private Key decryption password:")
        self.priv_key_pass_entry = tk.Entry(root, show="*")

        self.publ_key_label = tk.Label(root, text="Public Key userId:")
        self.publ_key_entry = tk.Entry(root)

        self.algorithm_label = tk.Label(root, text="Encryption algorithm:")

        self.algorithm_var = tk.StringVar()
        self.algorithm_var.set("Cast5")  # Default key size
        self.algorithm_cast5 = tk.Radiobutton(root, text="Cast5", variable=self.algorithm_var, value="Cast5")
        self.algorithm_aes128 = tk.Radiobutton(root, text="AES128", variable=self.algorithm_var, value="AES128")

        self.destination_label = tk.Label(root, text="Destination file name (without .txt suffix):")
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
        self.priv_key_pass.pack(pady=5)
        self.priv_key_pass_entry.pack(pady=5)
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
        priv_key_user_id = self.priv_key_entry.get()
        priv_key_pass = self.priv_key_pass_entry.get()
        publ_key_user_id = self.publ_key_entry.get()
        algorithm = self.algorithm_var.get()
        destination_file = self.destination_entry.get()

        # if text is None or (encryption is None and publ_key_user_id is None) or (authentication is None and priv_key_user_id is None) or destination_file is None:
        #     tk.messagebox.showinfo("Error", "Please enter all required information")
        #     return
        text = """Things fall apart and time breaks your heart
I wasn't there, but I know
She was your girl, you showed her the world
You fell out of love and you both let go
She was cryin' on my shoulder, all I could do was hold her
Only made us closer until July
Now I know that you love me, you don't need to remind me
I should put it all behind me, shouldn't I?"""

        encryption = False
        authentication = True
        compress = False
        radix64 = False
        priv_key_user_id = 'lea@gmail.com'
        priv_key_pass = 'lea'
        publ_key_user_id = 'nikola@gmail.com'
        algorithm = 'AES128'
        destination_file = 'test_auth_samo'
        text = text.encode()
        
        # Load private key
        if authentication:
            private_key = self.parentWindow.getPrivateKey(priv_key_user_id).decrypt(priv_key_pass)
            public_key_id = self.parentWindow.getPrivateKey(priv_key_user_id).keyId
            
            # Hash the message with SHA-1
            digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
            digest.update(text)
            hashed_message = digest.finalize()

            # Encrypt the hashed message with the private key using rsa algorithm
            signature = private_key.sign(hashed_message, padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA1())

            # Append the signature to the message

            appended_data = {
                "authenticated" : "True",
                "signature" : base64.b64encode(signature).decode('utf-8'),
                "public_key_id" : public_key_id
            }

            # print(text)

            appended_data = json.dumps(appended_data)
            text = text.decode() + "appended_data" + appended_data
            text = text.encode()

        if compress:
            # Compress the message
            compressed_message = utils.zip_data(text)
            text = compressed_message

        
        # Load public key
        if encryption:
            # Generate random 128-bit session key
            session_key = os.urandom(16)

            # Encrypt the message with the session key
            if algorithm == "Cast5":
                iv = os.urandom(8)
                cipher = Cipher(algorithms.CAST5(session_key), modes.CBC(iv), backend=default_backend())
                block_size = algorithms.CAST5.block_size
            elif algorithm == "AES128":
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
                block_size = algorithms.AES.block_size

            # import pdb
            # pdb.set_trace()

            padder = sym_padding.PKCS7(block_size).padder()
            text = padder.update(text) + padder.finalize()
            encryptor = cipher.encryptor()
            text = encryptor.update(text) + encryptor.finalize()

            public_key = self.parentWindow.getPublicKey(publ_key_user_id).publicKey
            public_key_id = self.parentWindow.getPublicKey(publ_key_user_id).keyId

            # Encrypt the session key with the public key
            encrypted_session_key = public_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))

            # Append the encrypted session key to the message

            appended_data = {
                "encrypted" : "True",
                "algorithm" : algorithm,
                "iv" : base64.b64encode(iv).decode('utf-8'),
                "public_key_id" : public_key_id,
                "encrypted_session_key" : base64.b64encode(encrypted_session_key).decode('utf-8')
            }

            appended_data = json.dumps(appended_data)
            text = base64.b64encode(text).decode('utf-8') + "appended_data" + appended_data
            text = text.encode()

        if radix64:
            # Encode the message with radix64
            text = utils.encode_radix64(text)
        
        # if (encryption is True or authentication is True or radix64 is True) and compress is False:
        #     text = text.decode()

        # if encryption is False and authentication is False and compress is True and radix64 is False:
        #     with open(f"./../Messages/{destination_file}.txt", "wb") as file:
        #         file.write(text)
        #         file.flush()
        # else:
        #     with open(f"./../Messages/{destination_file}.txt", "w") as file:
        #         file.write(text)
        #         file.flush()

        text = text.decode()

        with open(f"./../Messages/{destination_file}.txt", "w") as file:
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

    def open_send_button_gui(self):
        # Create a new window for key generation GUI
        send_window = tk.Toplevel(self.root)
        send_app = SendMessageGUI(send_window)


def main():
    root = tk.Tk()
    app = ApplicationGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
