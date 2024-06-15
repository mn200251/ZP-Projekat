import os
import sys
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

from MainApplicationGUI import MainApplicationGUI
from KeyRing import *


def init():
    global privateKeyRing, publicKeyRing

    if len(sys.argv) != 2:
        print("Error: One argument is expected.")
        sys.exit(1)

    userPath = sys.argv[1]
    print(f"Welcome user: {userPath}!")

    current_directory = os.getcwd()


    if not os.path.exists("Messages"):
        try:
            os.makedirs("Messages")

            print(f"Messages folder created.")
        except Exception as e:
            print(f"Error creating Mesages folder: {e}")
            sys.exit(1)

    new_working_directory = os.path.join(current_directory, userPath)

    if not os.path.exists(new_working_directory):
        try:
            os.makedirs(new_working_directory)
            # os.chdir(new_working_directory)

            # os.makedirs(os.path.join(new_working_directory, "PrivateKeys"))
            # os.makedirs(os.path.join(new_working_directory, "PublicKeys"))

            # os.makedirs(os.path.join(new_working_directory, "KeyRings", privateKeyRingName))
            # os.makedirs(os.path.join(new_working_directory, "KeyRings", publicKeyRingName))

            print(f"Directory {new_working_directory} created.")
        except Exception as e:
            print(f"Error creating directories: {e}")
            sys.exit(1)

    os.chdir(new_working_directory)

    if not os.path.exists((os.path.join(new_working_directory, "PrivateKeys"))):
        os.makedirs(os.path.join(new_working_directory, "PrivateKeys"))

    if not os.path.exists((os.path.join(new_working_directory, "PublicKeys"))):
        os.makedirs(os.path.join(new_working_directory, "PublicKeys"))


    # if privateKeyRing is None:
    #     privateKeyRing = PrivateKeyRing()
    # if publicKeyRing is None:
    #     publicKeyRing = PublicKeyRing()

    privateKeyRing = privateKeyRing.tryLoadFromDisk(privateKeyRingName)
    publicKeyRing.tryLoadFromDisk(publicKeyRingName)




def main():
    init()

    root = tk.Tk()
    app = MainApplicationGUI(root)

    app.refreshRings()  # for loading saved JSON

    root.mainloop()


if __name__ == "__main__":
    main()




