from pyhocon import ConfigFactory
import requests
import pprint

conf = ConfigFactory.parse_file("./secrets.conf")

headers = {
    "x-apikey": conf.get("api_key")
}

def sendFile(path):
    files = {'file': open(path)}
    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files ) 
    return response

def readResponse(uploadResponse):

    return requests.get("https://www.virustotal.com/api/v3/analyses/{}".format(uploadResponse["data"]["id"]), headers=headers)

def printer(dataDict):
    pp = pprint.PrettyPrinter()
    pp.pprint(dataDict)

test = sendFile("./LICENSE")
printer(test.json())
printer(readResponse(test.json()).json())

