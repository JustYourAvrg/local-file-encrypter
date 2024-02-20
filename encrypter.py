import sys
import string
import random
import pyperclip
import os
import shutil
import subprocess

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from faker import Faker
from tkinter import messagebox
from werkzeug.security import generate_password_hash
from pathlib import Path

fake = Faker()


FILE_PATH = ""
MIXED_ASCII = string.ascii_letters + string.digits + string.punctuation
MIXED_ASCII = ''.join(random.sample(MIXED_ASCII, len(MIXED_ASCII)))


def generate_decrypter_password():
    SECURE_PASSWORD = ""

    randWords = [fake.word() for _ in range(128)]
    for _ in range(6):
        SECURE_PASSWORD += random.choice(randWords)
        for _ in range(4):
            SECURE_PASSWORD += MIXED_ASCII[random.randint(0, len(MIXED_ASCII) - 1)]
    
    SECURE_PASSWORD = SECURE_PASSWORD[:26]
    
    pyperclip.copy(SECURE_PASSWORD)
    messagebox.showinfo("Decrypter Password", f"Your decrypter's password has been copied to the clipboard.")

    return SECURE_PASSWORD


def get_path():
    if len(sys.argv) > 1:
        FILE_PATH = str(sys.argv[1])
        main(FILE_PATH)
    else:
        messagebox.showerror("No file", "No file was selected to encrypt.")
        return


def get_data_from_file(file):
    with open(file, 'rb') as f:
        data = f.read()
    
    return data


def turn_into_executable(path):
    path = str(path)

    try:
        pyinstaller_path = shutil.which("pyinstaller")
        if not pyinstaller_path:
            messagebox.showerror("PyInstaller not found", "PyInstaller was not found on your system. Please install it using 'pip install pyinstaller'.")
            install_pyinstaller = messagebox.askyesno("Install PyInstaller?", "PyInstaller was not found on your system. Do you want to install it now?")
            if install_pyinstaller:
                subprocess.run(["pip", "install", "pyinstaller"])
            return
        
        subprocess.run([pyinstaller_path, "--onefile", path])

        os.remove(f"{path.split('.')[0]}.py")
        os.remove(f"{path.split('.')[0]}.spec")

        exe_path = Path(__file__).parent / f"dist/{os.path.basename(path).split('.')[0]}.exe"
        shutil.move(exe_path, Path(__file__).parent / f"{os.path.basename(path).split('.')[0]}.exe")

        shutil.rmtree(Path(__file__).parent / "build")
        shutil.rmtree(Path(__file__).parent / "dist")

        messagebox.showinfo("Executable created", f"The decrypter has been created as '{os.path.basename(path).split('.')[0]}.exe'.")
    
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")


def make_decrypter(path, aes_key, hmac_key, decrypter_password):
    decrypyter_path = Path(__file__).parent / f"decrypter_{os.path.basename(path).split('.')[0]}.py"

    with open(decrypyter_path, 'w') as f:
        f.write(f'''
import sys
import os
import time

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from tkinter import simpledialog, messagebox
from werkzeug.security import check_password_hash


FILE_PATH = ""
aes_key = {aes_key}
hmac_key = {hmac_key}
decrypter_password = """{decrypter_password}"""


def get_password_input() -> bool:
    input_password = simpledialog.askstring("Decrypter password", "What is your password for the decrypter: ")
    if check_password_hash(decrypter_password, input_password):
        return True
    
    return False


def get_path():
    if get_password_input():
        if len(sys.argv) > 1:
            FILE_PATH = str(sys.argv[1])
            main(FILE_PATH)
    else:
        messagebox.showerror("Wrong password", "The wrong password was entered")


def main(file_path):
    with open(file_path, 'rb') as f:
        tag = f.read(32)
        nonce = f.read(8)
        ciphertext = f.read()

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(nonce + ciphertext)
    try:
        hmac.verify(tag)
    except ValueError:
        messagebox.showerror("Error", "The message is not authentic.")
        return
    
    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)
    data = cipher.decrypt(ciphertext)

    with open(f"decrypted_{os.path.basename(path).split('.')[0]}.txt", 'wb') as f:
        f.write(data)

        
get_path()
''')

    turn_into_executable(decrypyter_path)
        

def main(path):
    data = get_data_from_file(path)
    aes_key = get_random_bytes(16)
    hmac_key = get_random_bytes(16)

    cipher = AES.new(aes_key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(data)

    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    tag = hmac.update(cipher.nonce + ciphertext).digest()
    
    with open(f"encrypted_{os.path.basename(path).split('.')[0]}", 'wb') as f:
        f.write(tag)
        f.write(cipher.nonce)
        f.write(ciphertext)
    
    delete_original_file = messagebox.askyesno("Delete original file?", f"The file has been encrypted and saved as 'encrypted_{os.path.basename(path)}'. Do you want to delete the original file?")
    if delete_original_file:
        os.remove(path)

    decrypter_password = generate_decrypter_password()
    encrypted_decrypter_password = generate_password_hash(decrypter_password, "scrypt")
    
    make_decrypter(path, aes_key, hmac_key, encrypted_decrypter_password)


get_path()
