import hashlib
import sys
from tools.reveal_file import *
from tools.virus_total import *
import time
from tools.file_signatures import *

def analyze():
    image = input("Enter image: ")
    print("Extracting file...")
    time.sleep(2)
    try:
        output = lsb.reveal(image)
        output += "==="
        output = base64.b64decode(output)

        check_file_header(output)

        time.sleep(1)

        VT_hash_scan(output)
    except FileNotFoundError:
        print("\nError, while extracting file!\n")




