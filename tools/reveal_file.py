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
        if output != None:
            output += "==="
            # decoding back to binary from base64
            output = base64.b64decode(output)
            # writing binary into a file

            print("\n -> File extracted as secret_file <-")
            with open("secret_file", "wb") as file:
                file.write(output)
        else:
            print("\n-> No file found <-")
    except FileNotFoundError:
        print("Error, while extracting file!")
        sys.exit(0)