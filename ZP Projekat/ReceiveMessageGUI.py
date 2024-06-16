import base64
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox, simpledialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import utils
import json
from cryptography.hazmat.primitives import padding as sym_padding


class ReceiveMessageGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Receive a message")
        self.root.geometry("300x150")

        self.browse_label = tk.Label(root, text="Choose a message to decrypt:")
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browsed_file = tk.Label(root, text="")

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_message)

        # Pack labels and buttons
        self.browse_label.pack(pady=5)
        self.browse_button.pack(pady=5)
        self.browsed_file.pack(pady=5)
        self.decrypt_button.pack(pady=10)


    def browse_file(self):
        # Open a file dialog to select a file
        self.file_path = filedialog.askopenfilename(initialdir=f"{os.getcwd()}/../Messages", title="Select a file", filetypes=[("All files", "*.*")])
        self.browsed_file.config(text=self.file_path.split("/")[-1])


    def decrypt_message(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a message file.")
            return
        
        compressed_last = False

        # Depending on whether or not the last stage of sending the message was compression, the message will be read in bytes or string format
        try:
            with open(self.file_path, "r") as file:
                text = file.read()
        except Exception as e:
            try:
                with open(self.file_path, "rb") as file:
                    text = file.read()
                    compressed_last = True
            except Exception as e:
                messagebox.showerror("Error", f"Error reading the file: {e}")
                return
            

        if not compressed_last:
            # Radix64 decode the message
            if utils.is_radix64(text):
                text = utils.radix64_decode(text)
                if not utils.is_gzipped(text):
                    text = text.decode()
       
            # Decrypt the message if not in zip format
            if not isinstance(text, bytes) and "appended_data_encr" in text:
                text, appended_data = text.split("appended_data_encr")
                text = base64.b64decode(text)
                appended_data = json.loads(appended_data)
                algorithm = appended_data['algorithm']
                iv = base64.b64decode(appended_data['iv'])
                encrypted_session_key = base64.b64decode(appended_data['encrypted_session_key'])

                # Prompt user for key password
                password = simpledialog.askstring("Password", "Enter the password for the private key under user ID: " + self.parentWindow.getPrivateKeyByKeyId(appended_data['public_key_id']).userId)

                private_key = self.parentWindow.getPrivateKeyByKeyId(appended_data['public_key_id']).decrypt(password)
                session_key = private_key.decrypt(encrypted_session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))

                if algorithm == "Cast5":
                    cipher = Cipher(algorithms.CAST5(session_key), modes.CBC(iv), backend=default_backend())
                    block_size = algorithms.CAST5.block_size
                elif algorithm == "AES128":
                    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
                    block_size = algorithms.AES.block_size

                # Decrypt the text
                decryptor = cipher.decryptor()
                text = decryptor.update(text) + decryptor.finalize()

                # Remove the padding
                unpadder = sym_padding.PKCS7(block_size).unpadder()
                text = unpadder.update(text) + unpadder.finalize()
                

        if not isinstance(text, bytes):
            text = text.encode()

        # Unzip the message
        if utils.is_gzipped(text):
            text = utils.unzip_data(text)

        if not isinstance(text, str):
            text = text.decode()

        # Verify the signature
        if "appended_data_auth" in text:
            text, appended_data = text.split("appended_data_auth")
            appended_data = json.loads(appended_data)
            print(text)

            digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
            digest.update(text.encode())
            hashed_message = digest.finalize()

            if self.parentWindow.getPublicKeyByKeyId(appended_data['public_key_id']).keyLegitimacy < 100:
                messagebox.showerror("Error", "User is not trusted")
                return
        
            public_key = self.parentWindow.getPublicKeyByKeyId(appended_data['public_key_id']).publicKey
            signature = base64.b64decode(appended_data['signature'])

            try:
                public_key.verify(signature, hashed_message, padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA1())
                print("Signature verified")
            except Exception as e:
                messagebox.showerror("Error", "Signature not verified")
                return


        if isinstance(text, bytes):
            text = text.decode()
        
        messagebox.showinfo("Success", "Message decrypted successfully!")
        save = messagebox.askyesno("Save", "Do you want to save the decrypted message?")

        if save:
            # Ask for the destination path
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            )
            
            if file_path:
                # Write the decrypted message to the file
                with open(file_path, 'w') as file:
                    file.write(text)
                messagebox.showinfo("Saved", f"Message saved successfully to {file_path}")
            else:
                messagebox.showinfo("Cancelled", "Save operation cancelled.")
        else:
            # Close the window or perform any other necessary action
            print("User chose not to save the message.")
            
        self.closeWindow()

    def closeWindow(self):
        self.root.destroy()


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
