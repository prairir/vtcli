from pyhocon import ConfigFactory
import requests
import pprint
import os
import time
import sys


def shutdown(message):
    print("script is turning off now\nbye :)")
    sys.exit("Error: {}".format(message))

def printer(dataDict):
    pp = pprint.PrettyPrinter().pprint(dataDict)

def readResponse(uploadResponse):
    responses = []
    for i in uploadResponse:
        response = requests.get("https://www.virustotal.com/api/v3/analyses/{}".format(i["data"]["id"]), headers=headers)
        responses.append(response.json())

    return responses

def sendFile(path):
    print(path)
    uploadFile = open(path)
    files = {'file': uploadFile}
    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files ) 
    return response

def sendFolder(path):
    responses = []
    for (dirPath, dirList, fileList) in os.walk(path):
        if len(fileList) <= 0:
            shutdown("Directory is empty")
        printer(fileList)
        for single in fileList:
            responses.append(sendFile(single).json())
            time.sleep(conf["folder_delay"])
        break
    return responses

def main():
    printer(readResponse(sendFolder(".")))

if __name__ == "__main__":
    conf = ConfigFactory.parse_file("./secrets.conf")

    headers = {
        "x-apikey": conf.get("api_key")
    }
    main() 

