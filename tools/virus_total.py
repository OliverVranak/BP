from datetime import datetime
import hashlib
import requests
import json

def VT_hash_scan(file):

    print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Calculating hashes...")
    # calculating md5,sha1 and sha256 hashes for signature analysis
    with open('report','a+') as report:

        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        md5_hash.update(file)
        sha1_hash.update(file)
        sha256_hash.update(file)
        report.write("\nMD5: {}\n".format(md5_hash.hexdigest()))
        report.write("SHA1: {}\n".format(sha1_hash.hexdigest()))
        report.write("SHA256: {}\n".format(sha256_hash.hexdigest()))

        #calling VirusTotal's API to check file hash
        url = f"https://www.virustotal.com/api/v3/files/{md5_hash.hexdigest()}"

        print("[*][" + datetime.now().strftime("%H:%M:%S") + "] Requesting file report from VirusTotal...")
        api_key = "495bd2b69040bb66abb725d31427cbcc3f77c3212f646348f5fb63e00cd65332"
        headers = {
            "Accept": "application/json",
            "x-apikey": api_key
                   }
        try:
            response = requests.request("GET", url, headers=headers)
            response = response.text
            response = json.loads(response)
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

                report.write("\nVirusTotal\n\n")
                report.write("score: {} / {}\n".format(malware_count,total_count))
                report.write("Size: {} bytes\n".format(response["data"]["attributes"]["size"]))
                report.write("Name of file: {}\n".format(response["data"]["attributes"]["meaningful_name"]))
                report.write("Reputation: {}\n".format(response["data"]["attributes"]["reputation"]))
                report.write("\nPE info\n")
                report.write("Offset: {}\n".format(response["data"]["attributes"]["pe_info"]["overlay"]["offset"]))
                report.write("Entropy: {}\n".format(response["data"]["attributes"]["pe_info"]["overlay"]["entropy"]))
                report.write("Filetype: {}\n".format(response["data"]["attributes"]["pe_info"]["overlay"]["filetype"]))
                for i in range(len(response["data"]["attributes"]["pe_info"]["sections"])):
                    report.write("\nName : {}\n".format(response["data"]["attributes"]["pe_info"]["sections"][i]["name"]))
                    report.write("Entropy : {}\n".format(response["data"]["attributes"]["pe_info"]["sections"][i]["entropy"]))
                    report.write("MD5 : {}\n".format(response["data"]["attributes"]["pe_info"]["sections"][i]["md5"]))
                report.write("\nImport list: \n")
                for i in range(len(response["data"]["attributes"]["pe_info"]["import_list"])):
                    report.write("{}\n".format(response["data"]["attributes"]["pe_info"]["import_list"][i]["library_name"]))

                report.write("-> For additional information visit : {}\n".format(response["data"]["links"]["self"]))
                print("[+][" + datetime.now().strftime("%H:%M:%S") + "] For more info please visit this link: ")
                print("[+][" + datetime.now().strftime("%H:%M:%S") + "] https://www.virustotal.com/gui/file/{}".format(
                    sha256_hash.hexdigest()))
                report.close()
        except :
            print("[+][" + datetime.now().strftime("%H:%M:%S") + "] Error occurred while requesting VirusTotal report.")
            report.close()




