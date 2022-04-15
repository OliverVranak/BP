from datetime import datetime
import hashlib
import requests
import os
from os.path import exists
import json

def VT_hash_scan(file):

    print("\n[*][" + datetime.now().strftime("%H:%M:%S") + "] Calculating hashes...")
    # calculating md5,sha1 and sha256 hashes for signature analysis
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    md5_hash.update(file)
    sha1_hash.update(file)
    sha256_hash.update(file)
    print("[+][" + datetime.now().strftime("%H:%M:%S") + "] md5:    " + md5_hash.hexdigest())
    print("[+][" + datetime.now().strftime("%H:%M:%S") + "] sha1:   " + sha1_hash.hexdigest())
    print("[+][" + datetime.now().strftime("%H:%M:%S") + "] sha256: " + sha256_hash.hexdigest())

    #calling VirusTotal's API to check file hash
    url = f"https://www.virustotal.com/api/v3/files/{md5_hash.hexdigest()}"

    print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Requesting file report from VirusTotal...")
    api_key = "495bd2b69040bb66abb725d31427cbcc3f77c3212f646348f5fb63e00cd65332"
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key
               }
    response = requests.request("GET", url, headers=headers)
    response = response.text
    response = json.loads(response)
    if exists("VirusTotal_report.txt"):
        os.remove("VirusTotal_report.txt")
    if "error" in response:
        print("\n[+][" + datetime.now().strftime("%H:%M:%S") + "] File Not found in VirusTotal Database. ")
    else:
        malware_count = 0
        total_count = 0
        for i in response["data"]["attributes"]["last_analysis_results"]:
            if response["data"]["attributes"]["last_analysis_results"][i]["category"] != "type-unsupported":
                if response["data"]["attributes"]["last_analysis_results"][i]["category"] != "failure":
                    total_count += 1
                    if response["data"]["attributes"]["last_analysis_results"][i]["category"] != "undetected":
                        malware_count += 1

        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] VirusTotal rating: ", malware_count, " / ", total_count)
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Names of the file: ")

        for i in response["data"]["attributes"]["names"]:
            print("\t\t",i)

        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] For more info please visit this link: ")
        print("[+][" + datetime.now().strftime("%H:%M:%S") + "] https://www.virustotal.com/gui/file/{}".format(sha256_hash.hexdigest()))





