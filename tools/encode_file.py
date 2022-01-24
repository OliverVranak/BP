from stegano import *
import base64
import sys

def encode_file_into_picture():
    filename = input("Enter path to your file: ")
    image = input("Enter picture: ")
    try:
        with open(filename, "rb") as bin_file:
            encoded_string = base64.b64encode(bin_file.read())

        message = encoded_string.decode()
        # hiding string into png file using LSB technique
        secret = lsb.hide(image, message)
        # saving the picture containing the message
        secret.save("secret_image.png")
    except FileNotFoundError:
        print("Error, files where not been found!")
        sys.exit(0)