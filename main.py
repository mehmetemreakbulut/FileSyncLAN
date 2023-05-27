import fcntl
import os
import socket
import difflib
import threading
from time import sleep
import tkinter as tk


import nacl.secret
import nacl.utils
from nacl.encoding import HexEncoder
from nacl.exceptions import CryptoError


UDP_IP = "0.0.0.0"
UDP_PORT = 12345
BUFFER_SIZE = 1024

# Initialize the file content and previous content
file_content = ""
previous_content = ""
file_path = "test.txt"
input_file_path = "input.txt"
# Listen for incoming file updates

#create 32 bytes long shared key
shared_key = b"12345678901234567890123456789012"
secret_box = nacl.secret.SecretBox(shared_key)
def decrypt_data(ciphertext):
    try:
        plaintext = secret_box.decrypt(ciphertext, encoder=HexEncoder)
        return plaintext.decode()
    except CryptoError:
        return None

    # Encrypt the data using the shared key
def encrypt_data(plaintext):
    return secret_box.encrypt(plaintext.encode(), encoder=HexEncoder)

def listen_for_updates():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, 12345))

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        print("Received file update from " + str(addr))
        plaintext = decrypt_data(data)
        if plaintext is None:
            print("Failed to decrypt data from", addr)
            continue
        update = plaintext.decode()
        apply_update(update)

# Apply the received file update
def apply_update(update):
    global file_content
    global previous_content

    if update.startswith("INIT"):
        file_content = update.split(" ", 1)[1]
        previous_content = file_content
        print("File content initialized.")
    elif update.startswith("DELTA"):
        delta = update.split(" ", 1)[1]
        updated_content = apply_delta(previous_content, delta)
        previous_content = updated_content
        file_content = updated_content
        print("File content updated.")
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, file_content)

# Apply the delta to the previous content to get the updated content
def apply_delta(previous_content, delta):
    updated_content = previous_content.splitlines()

    for line in delta.splitlines():
        if line.startswith("+ "):
            line_parts = line.split(" ", 2)
            line_num = int(line_parts[1])
            updated_content[line_num - 1] = line_parts[2]
        elif line.startswith("- "):
            line_parts = line.split(" ", 1)
            if len(line_parts) > 1:
                line_num = int(line_parts[1])
                if line_num <= len(updated_content):
                    del updated_content[line_num - 1]

    return "\n".join(updated_content)


# Send the file update to another client
def send_update(update, dest_ip, dest_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    encrypted_data = encrypt_data(update)#removed encode
    sock.sendto(encrypted_data, (dest_ip, dest_port))
    sock.close()

def send_updated_content(event=None):
    updated_content = text_widget.get("1.0", tk.END)
    delta = calculate_delta(previous_content, updated_content)
    print(delta)
    send_update("DELTA " + delta, "127.0.0.1", 12346)

# Calculate the delta between two versions of the file content
def calculate_delta(previous_content, updated_content):
    differ = difflib.ndiff(
        previous_content.splitlines(),
        updated_content.splitlines(),
    )

    delta = ""
    line_num = 0
    for line in differ:
        print(line)
        if line.startswith("+ "):
            delta += "+ " + str(line_num + 1) + " " + line[2:] + "\n"
            line_num += 1
        elif line.startswith("- "):
            delta += "- " + str(line_num + 1) + "\n"
            line_num -= 1

    return delta


def write_to_file(updated_content):
    with open(file_path, "w") as file:
        fcntl.flock(file, fcntl.LOCK_EX)  # Acquire an exclusive lock on the file
        print(updated_content)
        file.write(updated_content)
        fcntl.flock(file, fcntl.LOCK_UN)  # Release the lock
        
# Thread function to handle the listener
def listener_thread():
    listen_for_updates()

def create_gui():
    global text_widget

    root = tk.Tk()
    root.title("Shared File Editor")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_widget = tk.Text(frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
    text_widget.pack()

    scrollbar.config(command=text_widget.yview)

    text_widget.bind("<KeyRelease>", send_updated_content)

    root.mainloop()
    root.mainloop()

if __name__ == '__main__':
    # Usage example
    # Start the listener thread
    #listener_thread = threading.Thread(target=listener_thread)
    #listener_thread.start()
    #print("Listener thread started.")
    create_gui()
    last_update_time = 0
    while True:
        update_time = os.path.getmtime(input_file_path)
        if update_time > last_update_time:
            last_update_time = update_time
            with open(input_file_path, "r") as f:
                updated_content = f.read()
            delta = calculate_delta(previous_content, updated_content)
            print("delta:"  + delta)
            send_update("DELTA " + delta, "127.0.0.1", 12346)
            previous_content = updated_content
            file_content = updated_content
            print("File content updated.")
        sleep(1)
        
    # Continue with other operations, e.g., sending updates
    # Initialize the file content
    send_update("INIT Hello, World!", "127.0.0.1", 12345)

    # Update the file content and send the delta
    updated_content = "Hello, New World!"
    delta = calculate_delta(previous_content, updated_content)
    send_update("DELTA " + delta, "127.0.0.1", 12345)