import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image, ImageTk

def pad(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(plaintext)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def encrypt_file(key, file_path):
    with open(file_path, 'rb') as fo:
        plaintext = fo.read()

    encrypted_data = encrypt(key, plaintext)
    return encrypted_data

def browse_file():
    filename = filedialog.askopenfilename(title="Select File to Encrypt")
    if filename:
        upload_label.config(text="Selected File: " + os.path.basename(filename))
        encrypt_button.config(state=tk.NORMAL, command=lambda: encrypt_and_save(filename))

def encrypt_and_save(filename):
    if filename:
        encrypted_data = encrypt_file(key, filename)
        save_encrypted(encrypted_data, filename)

def save_encrypted(encrypted_data, filename):
    save_path = filedialog.asksaveasfilename(defaultextension=".encrypted", filetypes=[("Encrypted Files", "*.encrypted")], title="Save Encrypted File", initialfile=os.path.splitext(os.path.basename(filename))[0] + ".encrypted")
    if save_path:
        with open(save_path, 'wb') as fo:
            fo.write(encrypted_data)
        messagebox.showinfo("Encryption Successful", "File successfully encrypted and saved as:\n" + save_path)

def center_window(window):
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    x = (window.winfo_screenwidth() - width) // 2
    y = (window.winfo_screenheight() - height) // 2
    window.geometry('{}x{}+{}+{}'.format(width, height, x, y))

if __name__ == "__main__":
    key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'

    # Create the main window
    root = tk.Tk()
    root.title("FileCrypti - Secure your files")
    root.configure(bg="#1a1a1a")

    # Load lock image
    lock_img = Image.open("lock.png")
    lock_img = lock_img.resize((200, 200), Image.LANCZOS)
    lock_img = ImageTk.PhotoImage(lock_img)

    # Create a frame to hold all widgets
    main_frame = tk.Frame(root, bg="#1a1a1a")
    main_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)

    # Create widgets inside the frame
    label_header = tk.Label(main_frame, text="FileCrypti", font=("Arial", 40, "bold"), pady=20, bg="#1a1a1a", fg="#28a745")
    label_header.pack()

    image_label = tk.Label(main_frame, image=lock_img, bg="#1a1a1a")
    image_label.pack()

    upload_label = tk.Label(main_frame, text="Selected File: ", bg="#1a1a1a", fg="#28a745", font=("Arial", 16))
    upload_label.pack()

    upload_button = tk.Button(main_frame, text="Upload File", bg="#28a745", fg="white", font=("Arial", 20, "bold"), command=browse_file, highlightthickness=0, relief=tk.FLAT)
    upload_button.pack(pady=20)

    encrypt_button = tk.Button(main_frame, text="Encrypt", bg="#007bff", fg="white", font=("Arial", 24, "bold"), state=tk.DISABLED, highlightthickness=0, relief=tk.FLAT)
    encrypt_button.pack(pady=20)

    center_window(root)

    # Run the GUI
    root.mainloop()
