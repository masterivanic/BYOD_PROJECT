from tkinter import *
import tkinter as tk
import tkinter.scrolledtext as st

class InterfaceAPP:

    def __init__(self, master, header):
        self.master = master
        master.title(header)
        master.resizable(width=False, height=True)

        self.entry = st.ScrolledText(master, width=100, height=250,  font = ("Times New Roman", 15))
        self.entry.grid(column = 0, pady = 10, padx = 10)
    
    def insert_value(self, value):
        self.entry.insert(tk.INSERT, value)
        self.entry.configure(state='disabled')


if __name__ == "__main__":
    app = Tk()
    gui = InterfaceAPP(app, "Scan result")
    gui.insert_value("venez voir le moine....")
    app.mainloop()