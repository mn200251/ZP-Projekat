import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

from MainApplication import MainApplication


def main():
    root = tk.Tk()
    app = MainApplication(root)
    root.mainloop()


if __name__ == "__main__":
    main()
