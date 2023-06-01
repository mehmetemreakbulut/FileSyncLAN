import fcntl
from multiprocessing import Process
import multiprocessing
import os
import signal
import socket
import difflib
import struct
import subprocess
import sys
import threading
from time import sleep
import tkinter as tk
from typing import Tuple
import jc


import nacl.secret
import nacl.utils
from nacl.encoding import HexEncoder
from nacl.exceptions import CryptoError


UDP_IP = "0.0.0.0"
PORT = 12345
BROADCAST_PORT = 12346
BUFFER_SIZE = 1024

MULTICAST_IP = '224.0.0.1' 
# Initialize the file content and previous content
file_content = ""
previous_content = ""
file_name = 'shared_file.txt'

# Listen for incoming file updates

#create 32 bytes long shared key
shared_key = b"12345678901234567890123456789012"
secret_box = nacl.secret.SecretBox(shared_key)

ip_adresses = []
MY_IP  = ""
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
    global PORT

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((MULTICAST_IP, PORT))

    mreq = struct.pack("4sl", socket.inet_aton(MULTICAST_IP), socket.INADDR_ANY)

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        if str(addr[0]) == MY_IP:
            continue
        print("Received file update from " + str(addr))
        plaintext = decrypt_data(data)
        if plaintext is None:
            print("Failed to decrypt data from", addr)
            continue
        update = plaintext
        apply_update(update)

# Apply the received file update
def apply_update(update):
    global file_content
    global previous_content
    if update.startswith("INIT"):
        file_content = update.split(" ", 1)[1]
        previous_content = file_content
    elif update.startswith("DELTA"):
        delta = update.split(" ", 1)[1]
        updated_content = apply_delta(previous_content, delta)
        previous_content = updated_content
        file_content = updated_content
    cursor_position = text_widget.index(tk.INSERT)
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, file_content)
    text_widget.mark_set(tk.INSERT, cursor_position)

# Apply the delta to the previous content to get the updated content
def apply_delta(previous_content, delta):
    updated_content = previous_content.splitlines()
    count = 0
    for line in delta.splitlines():
        if line.startswith("+ "):
            line_parts = line.split(" ", 2)
            line_num = int(line_parts[1])
            count = line_num
            if len(updated_content) > line_num:
                if line_parts[2] == '':
                    updated_content.insert(line_num, u'\u200b')
                else:   
                    updated_content.insert(line_num, line_parts[2])
            else:
                if line_parts[2] == '':
                    updated_content.append(u'\u200b')
                else:   
                    updated_content.append(line_parts[2])
        elif line.startswith("- "):
            line_parts = line.split(" ", 1)
            line_num = int(line_parts[1])
            count = line_num
            del updated_content[line_num]
    return "\n".join(updated_content)


# Send the file update to another client
def send_update(update, dest_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    MULTICAST_TTL = 2

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
    encrypted_data = encrypt_data(update)#removed encode
    sock.sendto(encrypted_data, (MULTICAST_IP, dest_port))
    sock.close()

def send_updated_content(event=None):
    global previous_content
    global PORT
    global ip_adresses
    updated_content = text_widget.get("1.0", tk.END)
    delta = calculate_delta(updated_content)
    send_update("DELTA " + delta,  PORT)

# Calculate the delta between two versions of the file content
def calculate_delta(updated_content):

    global previous_content
    differ = difflib.ndiff(
        previous_content.splitlines(),
        updated_content.splitlines(),
    )
    previous_content = updated_content
    delta = ""
    line_num = 0
    for line in differ:
        if line.startswith("+ "):
            delta += "+ " + str(line_num) + " " + line[2:] + "\n"
            line_num += 1
        elif line.startswith("- "):
            delta += "- " + str(line_num) + "\n"
            #line_num -= 1
        elif line.startswith("? "):
            continue
        else:
            line_num += 1
    return delta

        
# Thread function to handle the listener
def listener_thread():
    listen_for_updates()

def save_text_to_file():
    global previous_content
    with open(file_name, 'w') as file:
        file.write(previous_content)
def create_gui():
    global text_widget
    global previous_content
    root = tk.Tk()
    root.title("main")

    frame = tk.Frame(root)
    frame.pack(pady=10)

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    text_widget = tk.Text(frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
    text_widget.pack()

    scrollbar.config(command=text_widget.yview)

    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, previous_content)
    text_widget.bind("<KeyRelease>", send_updated_content)
    save_button = tk.Button(root, height=1, width=10, text="Save",
                    command=save_text_to_file)
 
    save_button.pack()


    root.mainloop()

def listen_udp():
    
    global ip_adresses
    global file_content
    global previous_content
    global BROADCAST_PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, 12346))

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        ip_adresses.append(addr[0])
        print("received message:", data.decode())
        print("received from:", addr)
        if data.decode() == "hello":
            new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            new_sock.bind(('',0))
            print(previous_content)
            new_sock.sendto(previous_content.encode(), (addr[0], BROADCAST_PORT))
            new_sock.close()
        else:
            previous_content = data.decode()[:-1]



def udp_broadcast():
    global BROADCAST_PORT
    hello_message = "hello"
    data = hello_message.encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)
    sock.sendto(data,('<broadcast>',BROADCAST_PORT))
    sock.close()

def get_network_data()-> Tuple[str, str]:
    if_config_process = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout.strip()
    result = jc.parse('ifconfig', if_config_process )
    my_ip = 0
    mask = 0

    for a in result:
        if(a['name']=='en0'):
            my_ip=a['ipv4_addr']
            mask = a['ipv4_mask']
            
    return my_ip, mask


if __name__ == '__main__':
    # Usage example
    # Start the listener thread
    network_data = get_network_data() 
    MY_IP = network_data[0]
    udp_broadcast()
    listen_udp_process = threading.Thread(target=listen_udp)
    listen_udp_process.start()

    listener_process =  threading.Thread(target=listener_thread)
    listener_process.start()
    #print("Listener thread started.")
    create_gui()

    close_command = input("Press write CLOSE to close the program.\n")
    if close_command == "CLOSE":
        os.kill(os.getpid(),signal.SIGKILL)

