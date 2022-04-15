from stegano import *
import base64
from os.path import exists
from datetime import datetime


def reveal_file_from_picture():
    image = input("\n[->] Enter image: ")
    if not exists(image):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Image was not found!")
        return
    try:
        # exctracting the file from picture
        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Extracting...")
        output = lsb.reveal(image)
        try:
            output += "==="
            # decoding back to binary from base64
            output = base64.b64decode(output)
            # writing binary into a file
        except:
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Nothing has been found!\n")
            return

        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] File saved as secret_file")
        with open("secret_file", "wb") as file:
            file.write(output)
        file.close()

    except Exception as e:
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Error while extracting file!")
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] " + str(e))
        return