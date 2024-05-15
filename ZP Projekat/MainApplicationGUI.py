import tkinter as tk
from tkinter import ttk

from KeyGenerationGUI import KeyGenerationGUI, privateKeyRing, publicKeyRing
from KeyImportGUI import KeyImportGUI
from KeyExportGUI import KeyExportGUI


class MainApplicationGUI:
    def __init__(self, root):
        self.buttonWidth = 20
        self.buttonHeight = 2

        self.root = root
        self.root.title("ZP Projekat")
        self.root.geometry("1400x800")

        # Create a frame for the buttons
        self.button_frame = tk.Frame(root)
        self.button_frame.pack(side="left", fill="y")

        # Create buttons for the main functionalities inside the frame
        self.generate_button = tk.Button(self.button_frame, text="Generate RSA Keys", command=self.generate_keys,
                                         width=self.buttonWidth, height=self.buttonHeight)
        self.generate_button.pack(pady=10)

        self.import_button = tk.Button(self.button_frame, text="Import Key", command=self.import_key,
                                       width=self.buttonWidth, height=self.buttonHeight)
        self.import_button.pack(pady=10)

        self.export_button = tk.Button(self.button_frame, text="Export Key", command=self.export_key,
                                       width=self.buttonWidth, height=self.buttonHeight)
        self.export_button.pack(pady=10)

        self.send_message_button = tk.Button(self.button_frame, text="Send Message", command=self.send_message,
                                             width=self.buttonWidth, height=self.buttonHeight)
        self.send_message_button.pack(pady=10)

        self.receive_message_button = tk.Button(self.button_frame, text="Receive Message", command=self.receive_message,
                                                width=self.buttonWidth, height=self.buttonHeight)
        self.receive_message_button.pack(pady=10)

        headline1 = tk.Label(root, text="Private Key Ring", font=("Arial", 14, "bold"))
        headline1.pack()

        # Create a frame for the tables
        self.tables_frame = tk.Frame(root)
        self.tables_frame.pack(side="right", fill="both", expand=True)

        # Create the first Treeview widget

        self.privateKeyRingTable = ttk.Treeview(self.tables_frame)
        self.privateKeyRingTable["columns"] = ("Timestamp", "Key ID", "Public Key", "Encrypted Private Key", "User ID")

        # Define column headings for the first table
        self.privateKeyRingTable.heading("#0", text="Index")
        self.privateKeyRingTable.heading("Timestamp", text="Timestamp")
        self.privateKeyRingTable.heading("Key ID", text="Key ID")
        self.privateKeyRingTable.heading("Public Key", text="Public Key")
        self.privateKeyRingTable.heading("Encrypted Private Key", text="Encrypted Private Key")
        self.privateKeyRingTable.heading("User ID", text="User ID")

        self.privateKeyRingTable.column("#0", width=50, anchor="center")
        self.privateKeyRingTable.column("Timestamp", width=150, anchor="center")
        self.privateKeyRingTable.column("Key ID", width=150, anchor="center")
        self.privateKeyRingTable.column("Public Key", width=100, anchor="center")
        self.privateKeyRingTable.column("Encrypted Private Key", width=250, anchor="center")
        self.privateKeyRingTable.column("User ID", width=150, anchor="center")

        # Pack the first Treeview widget
        self.privateKeyRingTable.pack(expand=True, fill="both")

        headline2 = tk.Label(self.tables_frame, text="Public Key Ring", font=("Arial", 14, "bold"))
        headline2.pack()

        # Create the second Treeview widget

        self.publicKeyRingTable = ttk.Treeview(self.tables_frame)
        self.publicKeyRingTable["columns"] = (
        "Timestamp", "Key ID", "Public Key", "Owner Trust", "User ID", "Key Legitimacy", "Signatures",
        "Signature Trusts")

        # Define column headings for the second table
        self.publicKeyRingTable.heading("#0", text="Index")
        self.publicKeyRingTable.heading("Timestamp", text="Timestamp")
        self.publicKeyRingTable.heading("Key ID", text="Key ID")
        self.publicKeyRingTable.heading("Public Key", text="Public Key")
        self.publicKeyRingTable.heading("Owner Trust", text="Owner Trust")
        self.publicKeyRingTable.heading("User ID", text="User ID")
        self.publicKeyRingTable.heading("Key Legitimacy", text="Key Legitimacy")
        self.publicKeyRingTable.heading("Signatures", text="Signatures")
        self.publicKeyRingTable.heading("Signature Trusts", text="Signature Trusts")

        self.publicKeyRingTable.column("#0", width=50, anchor="center")
        self.publicKeyRingTable.column("Timestamp", width=150, anchor="center")
        self.publicKeyRingTable.column("Key ID", width=150, anchor="center")
        self.publicKeyRingTable.column("Public Key", width=100, anchor="center")
        self.publicKeyRingTable.column("Owner Trust", width=100, anchor="center")
        self.publicKeyRingTable.column("User ID", width=150, anchor="center")
        self.publicKeyRingTable.column("Key Legitimacy", width=100, anchor="center")
        self.publicKeyRingTable.column("Signatures", width=150, anchor="center")
        self.publicKeyRingTable.column("Signature Trusts", width=150, anchor="center")

        # tags for key legitimacy column
        self.publicKeyRingTable.tag_configure('green', background='green')
        self.publicKeyRingTable.tag_configure('red', background='red')

        # Pack the second Treeview widget
        self.publicKeyRingTable.pack(expand=True, fill="both")



    @staticmethod
    def refreshRings(self):
        self.refreshPrivateKeyRing()
        self.refreshPublicKeyRing()

    def refreshPrivateKeyRing(self):
        self.privateKeyRingTable.delete(*self.privateKeyRingTable.get_children())

        index = 0
        for row in privateKeyRing.getAllKeys():
            self.privateKeyRingTable.insert("", "end", text=str(index), values=(row.timestamp, row.keyId, row.publicKey.public_numbers().n, row.encryptedPrivateKey, row.userId))

            index += 1


    def refreshPublicKeyRing(self):
        self.publicKeyRingTable.delete(*self.publicKeyRingTable.get_children())

        index = 0
        for row in publicKeyRing.getAllKeys():
            self.publicKeyRingTable.insert("", "end", text=str(index), values=(
            row.timestamp, row.keyId, row.publicKey.public_numbers().n, row.ownerTrust, row.userId, row.keyLegitimacy, row.signatures, row.signatureTrust))

            # tag = "red"
            # if row.keyLegitimacy == 100:
            #     tag = "green"
            #
            # # self.publicKeyRingTable.item(self.publicKeyRingTable.get_children()[-1], tags=(tag,))
            #
            # index = self.publicKeyRingTable.index(-1)
            # self.publicKeyRingTable.tag_configure(tag, background='green' if row.keyLegitimacy == 100 else 'red')
            # self.publicKeyRingTable.item(index, tags=(tag,))

            index += 1

    def generate_keys(self):
        keygen_window = tk.Toplevel(self.root)
        keygen_window.grab_set()  # prevents from focusing on main window when this one is active
        keygen_app = KeyGenerationGUI(keygen_window, self)

    def import_key(self):
        importWindow = tk.Toplevel(self.root)
        importWindow.grab_set()  # prevents from focusing on main window when this one is active
        publicKeyImporter = KeyImportGUI(importWindow, self)

    def export_key(self):
        exportWindow = tk.Toplevel(self.root)
        exportWindow.grab_set()  # prevents from focusing on main window when this one is active
        publicKeyExporter = KeyExportGUI(exportWindow, self)

    def send_message(self):
        # Implement the logic for sending a message
        pass

    def receive_message(self):
        # Implement the logic for receiving a message
        pass