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
import utils
import json
from cryptography.hazmat.primitives import padding as sym_padding

from cryptography.hazmat.primitives.asymmetric import rsa

class ReceiveMessageGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Receive a message")
        self.root.geometry("300x150")

        self.browse_label = tk.Label(root, text="Choose a message to decrypt:")
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_message)
        

        # Pack labels, entries, radio buttons, and button
        self.browse_label.pack(pady=5)
        self.browse_button.pack(pady=5)
        self.decrypt_button.pack(pady=10)


    def browse_file(self):
        self.file_path = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select a file", filetypes=[("All files", "*.*")])


    def decrypt_message(self):
        self.file_path = "../Messages/test_auth_samo.txt"
        if not self.file_path:
            messagebox.showerror("Error", "Please select a message file.")
            return
        
        with open(self.file_path, "r") as file:
            text = file.read()

        if utils.is_radix64(text):
            text = utils.radix64_decode(text)

        import pdb
        # pdb.set_trace()
        # Decrypt message
        if "appended_data" in text:
            try:
                text_try, appended_data = text.split("appended_data")
                text_try = base64.b64decode(text_try)
                appended_data = json.loads(appended_data)
            
                if appended_data['encrypted'] == "True":
                    text = text_try
                    algorithm = appended_data['algorithm']
                    iv = base64.b64decode(appended_data['iv'])
                    encrypted_session_key = base64.b64decode(appended_data['encrypted_session_key'])

                    private_key = self.parentWindow.getPrivateKeyByKeyId(appended_data['public_key_id']).decrypt('nikola')
                    session_key = private_key.decrypt(encrypted_session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))

                    if algorithm == "Cast5":
                        cipher = Cipher(algorithms.CAST5(session_key), modes.CBC(iv), backend=default_backend())
                        block_size = algorithms.CAST5.block_size
                    elif algorithm == "AES128":
                        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
                        block_size = algorithms.AES.block_size

                    # Decrypt the text
                    decryptor = cipher.decryptor()
                    decrypted_padded_text = decryptor.update(text) + decryptor.finalize()

                    # Remove the padding
                    unpadder = sym_padding.PKCS7(block_size).unpadder()
                    text = unpadder.update(decrypted_padded_text) + unpadder.finalize()
            except Exception as e:
                pass
                


        if utils.is_gzipped(text.encode()):
            text = utils.unzip_data(text.encode())


        if "appended_data" in text:
            text, appended_data = text.split("appended_data")
            appended_data = json.loads(appended_data)
            print(text)

            digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
            digest.update(text.encode())
            hashed_message = digest.finalize()
        
            public_key = self.parentWindow.getPublicKeyByKeyId(appended_data['public_key_id']).publicKey
            signature = base64.b64decode(appended_data['signature'])
            if public_key.verify(signature, hashed_message, padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA1()):
                print("Signature verified")
            else:
                print("Signature not verified")


        
        # text = text.decode()
        print(text)
        # print(appended_data)
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
        self.open_receive_button = tk.Button(root, text="Generate RSA Key Pair", command=self.open_receive_button_gui)
        self.open_receive_button.pack(pady=10)

    def open_receive_button_gui(self):
        # Create a new window for key generation GUI
        receive_window = tk.Toplevel(self.root)
        receive_app = ReceiveMessageGUI(receive_window)


def main():
    root = tk.Tk()
    app = ApplicationGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
