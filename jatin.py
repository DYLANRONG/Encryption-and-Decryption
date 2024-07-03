import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from Crypto.Random import get_random_bytes
import base64
import requests
from PIL import Image, ImageTk
import os

def download_icon(url, path):
    response = requests.get(url)
    if response.status_code == 200:
        with open(path, 'wb') as f:
            f.write(response.content)

# Download the icons if they don't exist
encrypt_icon_url = "https://img.icons8.com/?size=100&id=AmijW2MMWTQj&format=png&color=000000"
decrypt_icon_url = "https://img.icons8.com/?size=100&id=KHwBKfC119Qm&format=png&color=000000"
save_icon_url = "https://img.icons8.com/?size=100&id=oTenRvV1I0KP&format=png&color=000000"
load_icon_url = "https://img.icons8.com/?size=100&id=93396&format=png&color=000000"
encrypt_file_icon_url = "https://img.icons8.com/?size=100&id=PTw8ROJPaad_&format=png&color=000000"
decrypt_file_icon_url = "https://img.icons8.com/?size=100&id=111653&format=png&color=000000"
key_icon_url = "https://img.icons8.com/?size=100&id=V5YRgupCQp6G&format=png&color=000000"

encrypt_icon_path = "encrypt_icon.png"
decrypt_icon_path = "decrypt_icon.png"
save_icon_path = "save_icon.png"
load_icon_path = "load_icon.png"
encrypt_file_icon_path = "encrypt_file_icon.png"
decrypt_file_icon_path = "decrypt_file_icon.png"
key_icon_path = "key_icon.png"

if not os.path.exists(encrypt_icon_path):
    download_icon(encrypt_icon_url, encrypt_icon_path)
if not os.path.exists(decrypt_icon_path):
    download_icon(decrypt_icon_url, decrypt_icon_path)
if not os.path.exists(save_icon_path):
    download_icon(save_icon_url, save_icon_path)
if not os.path.exists(load_icon_path):
    download_icon(load_icon_url, load_icon_path)
if not os.path.exists(encrypt_file_icon_path):
    download_icon(encrypt_file_icon_url, encrypt_file_icon_path)
if not os.path.exists(decrypt_file_icon_path):
    download_icon(decrypt_file_icon_url, decrypt_file_icon_path)
if not os.path.exists(key_icon_path):
    download_icon(key_icon_url, key_icon_path)

def generate_key(key_size):
    return base64.urlsafe_b64encode(get_random_bytes(key_size)).decode('utf-8')

def generate_iv():
    return base64.urlsafe_b64encode(get_random_bytes(16)).decode('utf-8')

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256

def encrypt_message(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + ct_bytes)
    hmac_value = hmac.digest()
    return base64.b64encode(iv + ct_bytes + hmac_value)

def decrypt_message(encrypted_data, key):
    data = base64.b64decode(encrypted_data)
    iv = data[:16]
    ct = data[16:-32]
    hmac_value = data[-32:]
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(iv + ct)
    try:
        hmac.verify(hmac_value)
    except ValueError:
        raise ValueError("Message authentication failed!")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt

def on_encrypt():
    try:
        message = text_message.get("1.0", tk.END).strip()
        if not message:
            raise ValueError("Message cannot be empty!")
        key_size = int(key_length_var.get())
        key = generate_key(key_size // 8)  # Convert bits to bytes
        iv = generate_iv()  # Generate IV
        entry_key.delete(0, tk.END)
        entry_key.insert(tk.END, key)
        entry_iv.delete(0, tk.END)
        entry_iv.insert(tk.END, iv)
        encrypted_message = encrypt_message(message.encode(), base64.urlsafe_b64decode(key), base64.urlsafe_b64decode(iv))
        text_encrypted_message.delete("1.0", tk.END)
        text_encrypted_message.insert(tk.END, encrypted_message.decode('utf-8'))
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

def on_decrypt():
    try:
        encrypted_message = text_encrypted_message.get("1.0", tk.END).strip()
        key = entry_key.get().strip()
        if not encrypted_message or not key:
            raise ValueError("Encrypted message and key cannot be empty!")
        decrypted_message = decrypt_message(encrypted_message.encode(), base64.urlsafe_b64decode(key))
        text_decrypted_message.delete("1.0", tk.END)
        text_decrypted_message.insert(tk.END, decrypted_message.decode('utf-8'))
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def on_encrypt_file():
    try:
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        with open(file_path, "rb") as file:
            file_data = file.read()
        key_size = int(key_length_var.get())
        key = generate_key(key_size // 8)
        iv = generate_iv()
        entry_key.delete(0, tk.END)
        entry_key.insert(tk.END, key)
        entry_iv.delete(0, tk.END)
        entry_iv.insert(tk.END, iv)
        encrypted_data = encrypt_message(file_data, base64.urlsafe_b64decode(key), base64.urlsafe_b64decode(iv))
        save_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if not save_path:
            return
        with open(save_path, "wb") as file:
            file.write(encrypted_data)
        # Save key and IV to a separate file
        key_iv_path = save_path + ".key"
        with open(key_iv_path, "w") as key_iv_file:
            key_iv_file.write(f"{key}\n{iv}")
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"File encryption failed: {str(e)}")

def on_decrypt_file():
    try:
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        # Load key and IV from a separate file
        key_iv_path = file_path + ".key"
        with open(key_iv_path, "r") as key_iv_file:
            key, iv = key_iv_file.read().splitlines()
        decrypted_data = decrypt_message(encrypted_data, base64.urlsafe_b64decode(key))
        save_path = filedialog.asksaveasfilename()
        if not save_path:
            return
        with open(save_path, "wb") as file:
            file.write(decrypted_data)
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"File decryption failed: {str(e)}")

def on_save_enc_message():
    try:
        encrypted_message = text_encrypted_message.get("1.0", tk.END).strip()
        key = entry_key.get().strip()
        iv = entry_iv.get().strip()
        if not encrypted_message or not key or not iv:
            raise ValueError("There is no encrypted message, key, or IV to save!")
        save_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if not save_path:
            return
        with open(save_path, "w") as file:
            file.write(encrypted_message)
        # Save key and IV to a separate file
        key_iv_path = save_path + ".key"
        with open(key_iv_path, "w") as key_iv_file:
            key_iv_file.write(f"{key}\n{iv}")
        messagebox.showinfo("Success", "Encrypted message and key/IV saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Saving encrypted message failed: {str(e)}")

def on_load_enc_message():
    try:
        file_path = filedialog.askopenfilename(defaultextension=".enc")
        if not file_path:
            return
        with open(file_path, "r") as file:
            encrypted_message = file.read().strip()
        key_iv_path = file_path + ".key"
        with open(key_iv_path, "r") as key_iv_file:
            key, iv = key_iv_file.read().splitlines()
        text_encrypted_message.delete("1.0", tk.END)
        text_encrypted_message.insert(tk.END, encrypted_message)
        entry_key.delete(0, tk.END)
        entry_key.insert(tk.END, key)
        entry_iv.delete(0, tk.END)
        entry_iv.insert(tk.END, iv)
        messagebox.showinfo("Success", "Encrypted message and key/IV loaded successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Loading encrypted message failed: {str(e)}")

def on_refresh():
    # Clear all input fields and text areas
    text_message.delete("1.0", tk.END)
    entry_key.delete(0, tk.END)
    entry_iv.delete(0, tk.END)
    text_encrypted_message.delete("1.0", tk.END)
    text_decrypted_message.delete("1.0", tk.END)
    key_length_var.set(key_lengths[0])

app = tk.Tk()
app.title("AES Encryption and Decryption")

# Set up colors
bg_color = "#2e3f4f"
fg_color = "#ffffff"
button_color = "#007acc"
entry_bg_color = "#4f6a7a"

app.configure(bg=bg_color)

frame = tk.Frame(app, bg=bg_color)
frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Message Frame
message_frame = tk.LabelFrame(frame, text="Message", bg=bg_color, fg=fg_color)
message_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew", columnspan=4)
text_message = tk.Text(message_frame, height=5, width=50, bg=entry_bg_color, fg=fg_color)
text_message.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

# Key Frame
key_frame = tk.Frame(frame, bg=bg_color)
key_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew", columnspan=4)

# Load and display the key icon
key_icon = ImageTk.PhotoImage(Image.open(key_icon_path))
tk.Label(key_frame, image=key_icon, bg=bg_color).grid(row=0, column=0, padx=(0, 5), pady=5, sticky="e")

tk.Label(key_frame, text="Key:", bg=bg_color, fg=fg_color).grid(row=0, column=1, padx=5, pady=5, sticky="w")
entry_key = tk.Entry(key_frame, width=50, bg=entry_bg_color, fg=fg_color)
entry_key.grid(row=0, column=2, padx=5, pady=5, columnspan=2, sticky="w")

tk.Label(key_frame, text="IV:", bg=bg_color, fg=fg_color).grid(row=1, column=1, padx=5, pady=5, sticky="w")
entry_iv = tk.Entry(key_frame, width=50, bg=entry_bg_color, fg=fg_color)
entry_iv.grid(row=1, column=2, padx=5, pady=5, columnspan=2, sticky="w")

tk.Label(key_frame, text="Key Length:", bg=bg_color, fg=fg_color).grid(row=2, column=1, padx=5, pady=5, sticky="w")

# Define the options
key_lengths = ["128", "192", "256"]
key_length_var = tk.StringVar(value=key_lengths[0])

# Create the OptionMenu
key_length_menu = ttk.OptionMenu(key_frame, key_length_var, key_lengths[0], *key_lengths)
key_length_menu.grid(row=2, column=2, padx=5, pady=5, sticky="w")

# Load and display the icons
encrypt_icon = ImageTk.PhotoImage(Image.open(encrypt_icon_path))
decrypt_icon = ImageTk.PhotoImage(Image.open(decrypt_icon_path))
save_icon = ImageTk.PhotoImage(Image.open(save_icon_path))
load_icon = ImageTk.PhotoImage(Image.open(load_icon_path))
encrypt_file_icon = ImageTk.PhotoImage(Image.open(encrypt_file_icon_path))
decrypt_file_icon = ImageTk.PhotoImage(Image.open(decrypt_file_icon_path))

# Buttons Frame
buttons_frame = tk.Frame(frame, bg=bg_color)
buttons_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew", columnspan=4)
tk.Button(buttons_frame, text="Encrypt", image=encrypt_icon, compound=tk.LEFT, command=on_encrypt, bg=button_color, fg=fg_color).grid(row=0, column=0, padx=5, pady=5)
tk.Button(buttons_frame, text="Save Enc Message", image=save_icon, compound=tk.LEFT, command=on_save_enc_message, bg=button_color, fg=fg_color).grid(row=0, column=1, padx=5, pady=5)
tk.Button(buttons_frame, text="Load Enc Message", image=load_icon, compound=tk.LEFT, command=on_load_enc_message, bg=button_color, fg=fg_color).grid(row=0, column=2, padx=5, pady=5)
tk.Button(buttons_frame, text="Refresh", command=on_refresh, bg=button_color, fg=fg_color).grid(row=0, column=3, padx=5, pady=5)

# Encrypted Message Frame
encrypted_message_frame = tk.LabelFrame(frame, text="Encrypted Message", bg=bg_color, fg=fg_color)
encrypted_message_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew", columnspan=4)
text_encrypted_message = tk.Text(encrypted_message_frame, height=5, width=50, bg=entry_bg_color, fg=fg_color)
text_encrypted_message.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

# Decrypt Frame
decrypt_frame = tk.Frame(frame, bg=bg_color)
decrypt_frame.grid(row=5, column=0, padx=10, pady=5, sticky="ew", columnspan=4)
tk.Button(decrypt_frame, text="Decrypt", image=decrypt_icon, compound=tk.LEFT, command=on_decrypt, bg=button_color, fg=fg_color).grid(row=0, column=0, padx=5, pady=5)

# Decrypted Message Frame
decrypted_message_frame = tk.LabelFrame(frame, text="Decrypted Message", bg=bg_color, fg=fg_color)
decrypted_message_frame.grid(row=6, column=0, padx=10, pady=5, sticky="ew", columnspan=4)
text_decrypted_message = tk.Text(decrypted_message_frame, height=5, width=50, bg=entry_bg_color, fg=fg_color)
text_decrypted_message.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

# File Operations Frame
file_frame = tk.Frame(frame, bg=bg_color)
file_frame.grid(row=7, column=0, padx=10, pady=5, sticky="ew", columnspan=4)
tk.Button(file_frame, text="Encrypt File", image=encrypt_file_icon, compound=tk.LEFT, command=on_encrypt_file, bg=button_color, fg=fg_color).grid(row=0, column=0, padx=5, pady=5)
tk.Button(file_frame, text="Decrypt File", image=decrypt_file_icon, compound=tk.LEFT, command=on_decrypt_file, bg=button_color, fg=fg_color).grid(row=0, column=1, padx=5, pady=5)

app.mainloop()
