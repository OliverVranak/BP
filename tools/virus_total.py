import json
import sys
import hashlib
import requests
import time

def VT_hash_scan(file_hash):

    api_key = input("Enter VT API key:  ")
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    time.sleep(1)
    print("Requesting file report of given hash...")
    time.sleep(3)
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key
               }

    response = requests.request("GET", url, headers=headers)
    response = response.text
    print(response + "\n")