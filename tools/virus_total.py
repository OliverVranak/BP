import json
import sys
import hashlib
import requests
import time

def VT_hash_scan(file):

    print("\n[*] Calculating hashes...")
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    time.sleep(2)
    #calculating hashes of file
    md5_hash.update(file)
    sha1_hash.update(file)
    sha256_hash.update(file)
    print("[+] md5: " + md5_hash.hexdigest())
    print("[+] sha1: " + sha1_hash.hexdigest())
    print("[+] sha256: " + sha256_hash.hexdigest())
    print("\n")
    #url for virustotal
    url = f"https://www.virustotal.com/api/v3/files/{md5_hash.hexdigest()}"

    time.sleep(1)
    print("[*] Requesting file report from VirusTotal...")
    time.sleep(3)
    api_key = "495bd2b69040bb66abb725d31427cbcc3f77c3212f646348f5fb63e00cd65332"
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key
               }
    #get request for file report from VirusTotal
    response = requests.request("GET", url, headers=headers)
    response = response.text
    print(response + "\n")