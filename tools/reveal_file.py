import hashlib

from stegano import *
import base64
import sys
import time


def reveal_file_from_picture():
    image = input("Enter image: ")
    try:
        # exctracting the file from picture
        time.sleep(1)
        print("Extracting file...")
        time.sleep(2)
        output = lsb.reveal(image)
        try:
            output += "==="
            # decoding back to binary from base64
            output = base64.b64decode(output)
            # writing binary into a file
        except:
            print("File Not Found\n")
            print("Bytes exctracted\n")
            output = bytes(output,'utf-8')

        print("\n -> Saved as secret_file <-")
        with open("secret_file", "wb") as file:
            file.write(output)
        file.close()

    except FileNotFoundError:
        print("Error, while extracting file!")
        sys.exit(0)