from pyhocon import ConfigFactory
import requests
import pprint
import os
import time
import sys

conf = ConfigFactory.parse_file("./secrets.conf")

headers = {
    "x-apikey": conf.get("api_key")
}

def shutdown(message):
    print("script is turning off now\nbye :)")
    sys.exit("Error: {}".format(message))

def printer(dataDict):
    pp = pprint.PrettyPrinter().pprint(dataDict)

def readResponse(uploadResponse):
    params = []
    if(type(uploadResponse) is list):
        params = uploadResponse
    else: 
        params.append(uploadResponse.json())
    print(type(params))
    print(params)
    responses = []
    for i in params:
        if i["error"]:
            print("error")
            continue
        response = requests.get("https://www.virustotal.com/api/v3/analyses/{}".format(i["data"]["id"]), headers=headers)
        responses.append(response.json())

    return responses

def sendUrl(path):
    url = {'url': (None, path)}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=url )
    print(url)
    print(response.json())
    return response


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
    printer(readResponse(sendUrl("https://www.google.ca")))


    
main() 

