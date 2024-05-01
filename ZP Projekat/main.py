import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

from MainApplicationGUI import MainApplicationGUI
from KeyRing import *



def init():
    global privateKeyRing, publicKeyRing

    privateKeyRing = PrivateKeyRing()
    publicKeyRing = PublicKeyRing()

def main():
    init()

    root = tk.Tk()
    app = MainApplicationGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()




