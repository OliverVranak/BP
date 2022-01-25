import hashlib
import sys
from tools.reveal_file import *
from tools.virus_total import *
import time

def VT_analysis():
    reveal_file_from_picture()
    try:
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        with open("secret_file","rb") as file:
            time.sleep(1)
            print("\nCalculating hashes...")
            time.sleep(2)
            buffer = file.read()
            md5_hash.update(buffer)
            sha1_hash.update(buffer)
            sha256_hash.update(buffer)
        print("ms5: " + md5_hash.hexdigest())
        print("sha1: " + sha1_hash.hexdigest())
        print("sha256: " + sha256_hash.hexdigest())
        print("\n")
        VT_hash_scan(md5_hash.hexdigest())
    except FileNotFoundError:
        print("Error, File not found!")
        sys.exit(0)


