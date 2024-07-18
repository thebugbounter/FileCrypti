import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image, ImageTk

def pad(data):
    padder = padding.PKCS7(128).unpadder()
    unpadded_data = padder.update(data) + padder.finalize()
    return unpadded_data

def decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

def decrypt_file(key, file_path):
    with open(file_path, 'rb') as fo:
        encrypted_data = fo.read()

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    decrypted_data = decrypt(key, iv, ciphertext)
    return decrypted_data

def browse_encrypted_file():
    filename = filedialog.askopenfilename(title="Select Encrypted File to Decrypt")
    if filename:
        upload_label.config(text="Selected Encrypted File: " + os.path.basename(filename))
        if is_encrypted(filename):
            decrypt_button.config(state=tk.NORMAL, command=lambda: decrypt_and_save(filename))
        else:
            messagebox.showerror("Error", "The file you uploaded is not encrypted.")
            decrypt_button.config(state=tk.DISABLED)

def decrypt_and_save(filename):
    if filename:
        decrypted_data = decrypt_file(key, filename)
        if decrypted_data is not None:
            save_decrypted(decrypted_data, filename)
        else:
            messagebox.showerror("Error", "Failed to decrypt the file. Make sure it is a valid encrypted file.")

def save_decrypted(decrypted_data, filename):
    original_filename, _ = os.path.splitext(filename)
    save_path = filedialog.asksaveasfilename(defaultextension=".decrypted", filetypes=[("All Files", "*.*")], title="Save Decrypted File", initialfile=os.path.basename(original_filename) + ".decrypted")
    if save_path:
        with open(save_path, 'wb') as fo:
            fo.write(decrypted_data)
        messagebox.showinfo("Decryption Successful", "File successfully decrypted and saved as:\n" + save_path)

def is_encrypted(filename):
    with open(filename, 'rb') as fo:
        header = fo.read(16)
        return header != b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'

def center_window(window):
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry('{}x{}+{}+{}'.format(width, height, x, y))

if __name__ == "__main__":
    key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'

    # Create the main window
    root = tk.Tk()
    root.title("FileDecrypti")
    root.configure(bg="#000")

    # Load unlock image
    unlock_img = Image.open("lock.png")
    unlock_img = unlock_img.resize((200, 200), Image.LANCZOS)
    unlock_img = ImageTk.PhotoImage(unlock_img)

    # Create widgets
    label_header = tk.Label(root, text="FileDecrypti - Decrypt your files", font=("Arial", 40, "bold"), pady=50, bg="#000", fg="#28a745")
    label_header.pack()

    image_label = tk.Label(root, image=unlock_img, bg="#000")
    image_label.pack()

    upload_label = tk.Label(root, text="Selected Encrypted File: ", bg="#000", fg="#28a745", font=("Arial", 16))
    upload_label.pack()

    upload_button = tk.Button(root, text="Select Encrypted File", bg="#28a745", fg="white", font=("Arial", 20, "bold"), command=browse_encrypted_file, highlightthickness=0, relief=tk.FLAT)
    upload_button.pack(pady=20)

    decrypt_button = tk.Button(root, text="Decrypt", bg="#007bff", fg="white", font=("Arial", 24, "bold"), state=tk.DISABLED, highlightthickness=0, relief=tk.FLAT)
    decrypt_button.pack(pady=20)

    center_window(root)

    # Run the GUI
    root.mainloop()
