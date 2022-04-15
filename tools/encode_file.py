from stegano import *
import base64
import os
from datetime import datetime
from os.path import exists

def encode_file_into_picture():
    filename = input("\n[->] Enter file: ")
    if not exists(filename):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] File was not found!")
        return
    image = input("[->] Enter picture: ")
    if not exists(image):
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] Image was not found!")
        return

        #checking if file is bigger than image
    if os.stat(filename).st_size >= os.stat(image).st_size:
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] File is bigger than image.")
        return

    try:
        #opening file to be encoded
        with open(filename, "rb") as bin_file:
            encoded_string = base64.b64encode(bin_file.read())

        #converting encoded_string into string
        message = encoded_string.decode()
        print("\n[*][" + datetime.now().strftime("%H:%M:%S") + "] Encoding...")
        # hiding string into png file using LSB technique
        secret = lsb.hide(image, message)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] File was encoded into secret_image.png")
        # saving the picture containing the message
        secret.save("secret_image.png")
    except Exception as e:
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Error while encoding file!")
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] "+ str(e))
        return