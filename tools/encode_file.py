from stegano import *
import base64
import sys
import time
import os
def encode_file_into_picture():
    filename = input("[->] Enter file: ")
    image = input("[->] Enter picture: ")

    #checking if file is bigger than image
    if os.stat(filename).st_size >= os.stat(image).st_size:
        print("[+] File is bigger than image.")
        exit()

    try:
        #opening file to be encoded
        with open(filename, "rb") as bin_file:
            encoded_string = base64.b64encode(bin_file.read())

        #converting encoded_string into string
        message = encoded_string.decode()
        time.sleep(0.5)
        print("\n[*] Encoding...",end="")
        time.sleep(2.5)
        # hiding string into png file using LSB technique
        secret = lsb.hide(image, message)
        print("\n[+] File was encoded into secret_image.png")
        # saving the picture containing the message
        secret.save("secret_image.png")
    except FileNotFoundError:
        print("[+] Error while encoding files!")
        sys.exit(0)