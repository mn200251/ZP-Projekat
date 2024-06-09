import tkinter as tk

class SendMessageGUI:
    def __init__(self, root, parentWindow):
        self.parentWindow = parentWindow
        self.root = root
        self.root.title("Send a message")
        self.root.geometry("300x550")

        self.text_label = tk.Label(root, text="Text message:")
        self.text_entry = tk.Entry(root)

        self.receiver_label = tk.Label(root, text="Receiver:")
        self.receiver_entry = tk.Entry(root)


        self.encryption_checkbox_var = tk.IntVar()
        self.authentication_checkbox_var = tk.IntVar()
        self.compress_checkbox_var = tk.IntVar()
        self.radix64_checkbox_var = tk.IntVar()

        # Checkbox entries
        self.encryption_checkbox = tk.Checkbutton(root, text="Encrypt message", variable=self.encryption_checkbox_var)
        self.authentication_checkbox = tk.Checkbutton(root, text="Authenticate message", variable=self.authentication_checkbox_var) 
        self.compress_checkbox = tk.Checkbutton(root, text="Compress message", variable=self.compress_checkbox_var)
        self.radix64_checkbox = tk.Checkbutton(root, text="Radix64 encode message", variable=self.radix64_checkbox_var)
        
        self.priv_key_label = tk.Label(root, text="Private Key:")
        self.priv_key_entry = tk.Entry(root)

        self.publ_key_label = tk.Label(root, text="Public Key:")
        self.publ_key_entry = tk.Entry(root)

        self.algorithm_label = tk.Label(root, text="Encryption algorithm:")

        self.algorithm_var = tk.IntVar()
        self.algorithm_var.set("Cast5")  # Default key size
        self.algorithm_cast5 = tk.Radiobutton(root, text="Cast5", variable=self.algorithm_var, value="Cast5")
        self.algorithm_aes128 = tk.Radiobutton(root, text="AES128", variable=self.algorithm_var, value="AES128")

        self.destination_label = tk.Label(root, text="Destination path:")
        self.destination_entry = tk.Entry(root)

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        

        # Pack labels, entries, radio buttons, and button
        self.text_label.pack(pady=5)
        self.text_entry.pack(pady=5)
        self.receiver_label.pack(pady=5)
        self.receiver_entry.pack(pady=5)
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
        # name = self.name_entry.get()  # sta ce nam ovo ???
        # email = self.email_entry.get()
        # keySize = self.key_size_var.get()
        # passcode = self.password_entry.get()

        # if name is None or email is None or keySize is None or passcode is None:
        #     tk.messagebox.showinfo("Error", "Please enter all required information")
        #     return

        # if name == "" or email == "" or keySize is None or passcode == "":
        #     tk.messagebox.showinfo("Error", "Please enter all required information")
        #     return

        # # Show success message
        # tk.messagebox.showinfo("Success", "RSA Key pair generated successfully")

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
