# Concurrent File Editor

This program enables users on a Local Area Network (LAN) to concurrently edit the same file. It utilizes a graphical user interface (GUI) implemented using the `tkinter` library. The program uses delta encoding and encryption for transmitting file updates among the clients through multicasting.

## Installation

1. Clone the repository or download the source code files.
2. Install the required dependencies by running the following command:

   ```
   pip install -r requirements.txt
   ```

## Usage

To run the program, execute the following command:

```
python3 main.py
```

### GUI Overview

The program opens a GUI window that allows you to edit the shared file. The GUI consists of the following components:

- Text Area: The main area where you can view and edit the content of the shared file.
- Save Button: Clicking this button will save the current content of the file.
- Close Program: To close the program, enter "CLOSE" in the terminal window.

### Editing the Shared File

When you make changes in the text area, the program automatically applies delta encoding and encrypts the updated content. The encrypted update is then multicasted to other clients on the LAN. The clients receive the update, decrypt it, and apply it to their local file.

### File Synchronization

The program uses delta encoding to calculate the differences between the previous content and the updated content. This delta is then transmitted to other clients, allowing them to apply the changes without sending the entire file.

### Encryption

The file updates are encrypted using a shared key, which is a 32-byte long value. The shared key is used to initialize a secret box from the `nacl.secret` module. This ensures that the file updates are secure during transmission.

### Multicasting

The program utilizes multicasting to transmit file updates to other clients on the LAN. The clients listen for incoming updates and apply them to their local file.

## Notes

- The program assumes that all clients are connected to the same Local Area Network.
- The program retrieves the IP address and mask of the current machine automatically.
- The program broadcasts its IP address to discover other clients on the LAN.
- The GUI allows concurrent editing of the shared file by multiple clients.
- File updates are encrypted using a shared key to ensure secure transmission.

**Note:** Please ensure that the necessary permissions are granted to run the program and that the required dependencies are installed before running the program.
