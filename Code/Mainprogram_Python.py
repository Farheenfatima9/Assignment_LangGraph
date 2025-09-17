import json
import sys
import os
import requests


API_KEY='7c2da6fcb9e74ac070383740d4d3ddeb201dcd6bfa9ab7aefbd6ceaf44835f74'


def take_parameter_from_File(Content, Key_Value):
    if isinstance(Content, dict):
        for k, v in Content.items():
            if k == Key_Value:
                return v
            else:
                res= take_parameter_from_File(v, Key_Value)
                if res is not None:
                    return res
                
    elif isinstance(Content,list):
        for itm in Content:
            res= take_parameter_from_File(itm, Key_Value)
            if res is not None:
                return res

    else: 
        return None

def ip_address_score(ip_add):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_add}'

    headers = {
    "accept": "application/json", 
    "x-apikey": API_KEY}

    response = requests.get(url, headers=headers)
    data = json.loads(response.content)
    score = data["data"]["attributes"]["last_analysis_stats"]
    # print("VirusTotal Score:", score)
    return score


def hash_score_val(hash_val):
    url = f'https://www.virustotal.com/api/v3/files/{hash_val}'

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    data = json.loads(response.content)
    score = data["data"]["attributes"]["last_analysis_stats"]
    # print("VirusTotal Score:", score)
    return score
    


def ReadJsonFile(Filename):
    try: 
        with open(filename, 'r') as f:
            data=json.load(f)
            print("Contents are in json format.")
            ip_address=take_parameter_from_File(data, 'ip')
            hash_value=take_parameter_from_File(data, 'hash')

            if (ip_address is not None and hash_value is not None):
                ip_score=ip_address_score(ip_address)
                hash_score=hash_score_val(hash_value)
                print(f'IP Score: {ip_score}')
                print(f'Hash Score: {hash_score}')

            elif(ip_address is not None):
                print(ip_address)
                ip_score=ip_address_score(ip_address)
                print(f'IP Score: {ip_score}')

            elif(hash_value is not None):
                hash_score=hash_score_val(hash_value)
                print(f'Hash Score: {hash_score}')

            else:
                print("Hash Value and IP not exist in file.")

    except json.JSONDecodeError:
        print("File Contents are not in Json.")

    return None





if __name__== "__main__":
    print("Reading file from terminal ....")

    if len(sys.argv) < 2:
        print("File is not given. ")

    elif len(sys.argv) == 2 :
        filename = sys.argv[1]
        if filename.endswith(".json"):
            print("Json File")
            if os.path.exists(filename):
                print("File exists.")
                ReadJsonFile(filename)
            else:
                print("File dos not exist.")
                # sys.exit(1)
        else:
            print("File is not json.")
            # sys.exit(1)
    else:
        print("Too many files.")
        # sys.exit(1)
