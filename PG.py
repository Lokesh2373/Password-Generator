import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip

def generate_password():
    try:
        length = int(length_entry.get())
        if length < 6:
            messagebox.showerror("Error", "Password length should be at least 6 characters")
            return

        selected_types = []
        if letters.get():
            selected_types.append(string.ascii_letters)
        if numbers.get():
            selected_types.append(string.digits)
        if symbols.get():
            selected_types.append(string.punctuation)

        if not selected_types:
            messagebox.showerror("Error", "Please select at least one character type")
            return

        all_characters = ''.join(selected_types)
        password = ''.join(random.choices(all_characters, k=length))

        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
    except ValueError:
        messagebox.showerror('Error', 'Enter a valid number')

def toggle_password_visibility():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

def clipboard_copy():
    password = password_entry.get()
    pyperclip.copy(password)
    messagebox.showinfo("Copied", "Password copied to clipboard")

root = tk.Tk()
root.title("Password Generator")
root.geometry("400x250")
root.configure(background='#282c34')


style = ttk.Style()
style.configure("TLabel", background='#282c34', foreground='#61dafb', font=('Helvetica', 12))
style.configure("TCheckbutton", background='#282c34', foreground='#61dafb', font=('Helvetica', 10))
style.configure("TButton", background='#61dafb', foreground='black', font=('Helvetica', 10, 'bold'))


main_frame = ttk.Frame(root, padding="10 10 10 10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))


length_label = ttk.Label(main_frame, text="Password Length:")
length_label.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

length_entry = ttk.Entry(main_frame, width=10)
length_entry.grid(row=0, column=1, padx=5, pady=5)

letters = tk.BooleanVar()
letters_checkbox = ttk.Checkbutton(main_frame, text="Letters", variable=letters)
letters_checkbox.grid(row=1, column=0, padx=5, pady=5)

numbers = tk.BooleanVar()
numbers_checkbox = ttk.Checkbutton(main_frame, text="Numbers", variable=numbers)
numbers_checkbox.grid(row=1, column=1, padx=5, pady=5)

symbols = tk.BooleanVar()
symbols_checkbox = ttk.Checkbutton(main_frame, text="Symbols", variable=symbols)
symbols_checkbox.grid(row=1, column=2, padx=5, pady=5)

generate_button = ttk.Button(main_frame, text="Generate Password", command=generate_password)
generate_button.grid(row=2, column=0, columnspan=3, pady=10)

password_entry = ttk.Entry(main_frame, show="*", width=30)
password_entry.grid(row=3, column=0, columnspan=3, padx=5, pady=5)

show_password_var = tk.BooleanVar()
show_password_checkbox = ttk.Checkbutton(main_frame, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
show_password_checkbox.grid(row=4, column=0, padx=5, pady=5)

clipboard_button = ttk.Button(main_frame, text="Copy Password", command=clipboard_copy)
clipboard_button.grid(row=4, column=2, padx=5, pady=5)

root.mainloop()






