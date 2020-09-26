from pyhocon import ConfigFactory
import argparse
import requests
import pprint
import os
import time
import sys


# shut down and show error message
# takes a string error message
# returns None
def shutdown(message):
    print("script is turning off now\nbye :)")
    sys.exit("{}".format(message))

# just a pretty print wrapper
# takes any object
# returns None
def printer(dataDict):
    pp = pprint.PrettyPrinter().pprint(dataDict)

# reads the response
# takes a list or response object
# changes response object to list
# returns array of response objects dictonaries
def readResponse(uploadResponse):
    params = []
    # changes type to list if its not a list
    if(type(uploadResponse) is list):
        params = uploadResponse
    else: 
        params.append(uploadResponse.json())
    print(type(params))
    print(params)
    responses = []
    for i in params:
        if "error" in uploadResponse:
            continue

        response = requests.get("https://www.virustotal.com/api/v3/analyses/{}".format(i["data"]["id"]), headers=headers)
        responceObj = response.json()
        while responceObj.get("status") == "queued":
            response = requests.get("https://www.virustotal.com/api/v3/analyses/{}".format(i["data"]["id"]), headers=headers)
            responceObj = response.json()
        
        responses.append(responceObj)

    return responses

# sends a url to VT endpoint
# takes string
# returns response object
def sendUrl(path):
    url = {'url': (None, path)}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=url )
    # poop pants on error
    if response.status_code != requests.codes.ok:
        shutdown("error code: {}\nerror message: {}".format(response.json()["error"]["code"], response.json()["error"]["message"]))
    return response


# sends a file to VT endpoint
# takes file path as string
# returns response object
def sendFile(path):
    uploadFile = open(path)
    files = {'file': uploadFile}
    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files ) 
    # poop pants on error
    if response.status_code != requests.codes.ok:
        shutdown("error code: {}\nerror message: {}".format(response.json()["error"]["code"], response.json()["error"]["message"]))
    return response

# given a folder, uploads each file to VT
# takes a folder path
# returns a list of response objects
def sendFolder(path):
    responses = []
    for (dirPath, dirList, fileList) in os.walk(path):
        if len(fileList) <= 0:
            shutdown("Directory is empty")
        printer(fileList)
        for single in fileList:
            responses.append(sendFile(os.path.join(dirPath, single)).json())
            time.sleep(conf["folder_delay"])
        break
    return responses

def main():
    printer(readResponse(sendUrl("https://www.google.ca")))


    
if __name__ == "__main__":
    argparser = argparse.ArgumentParser(prog="vtcli", description="CLI tool for virus scanning with Virus Total")

    argparser.add_argument("value", nargs=1, metavar="File")

    arguements = argparser.parse_args()


    if len(sys.argv) <=1:
        argparser.print_help()
        shutdown("not enough arguements")

    if not arguements.value:
        argparser.print_help()
        shutdown("Need to specify a file or url to test")

    conf = ConfigFactory.parse_file("./secrets.conf")

    headers = {
        "x-apikey": conf.get("api_key")
    }
    main() 

