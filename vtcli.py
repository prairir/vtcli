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
    if(arguements.verbose):
        for out in dataDict:
            print(out[0])
            res = out[1].get("data").get("attributes").get("results")
            for x in res:
                cat = res[x].get("category")
                met = res[x].get("method")
                print("\n\n\tName: {} \n\tCategory: {}\n\tMethod: {}".format(x, cat, met))
        return
    if(arguements.raw):
        pprint.PrettyPrinter().pprint(dataDict)
        return

    for out in dataDict:
        print(out[0])
        res = out[1].get("data").get("attributes").get("stats")
        items = out[1].get("data").get("attributes").get("stats").items()
        for x in items:
            print("\t" + x[0] + " " +str(x[1]))
        

# reads the response
# takes a list or response object
# changes response object to list
# returns array of response objects dictonaries
def readResponse(uploadResponse):
    params = []
    # changes type to list if its not a list
    if(type(uploadResponse[0]) is list):
        params = uploadResponse
    else: 
        params.append(uploadResponse)
    responses = []
    for name, i in params:
        if "error" in i:
            continue

        response = requests.get("https://www.virustotal.com/api/v3/analyses/{}".format(i["data"]["id"]), headers=headers)
        responceObj = response.json()
        while responceObj.get("status") == "queued":
            response = requests.get("https://www.virustotal.com/api/v3/analyses/{}".format(i["data"]["id"]), headers=headers)
            responceObj = response.json()
        
        responses.append([name,responceObj])

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
    return [path, response.json()]


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
    return [path, response.json()]

# given a folder, uploads each file to VT
# takes a folder path
# returns a list of response objects
def sendFolder(path):
    responses = []
    for (dirPath, dirList, fileList) in os.walk(path):
        if len(fileList) <= 0:
            shutdown("Directory is empty")
        for single in fileList:
            responses.append(sendFile(os.path.join(dirPath, single)))
            time.sleep(conf["folder_delay"])
        break
    return responses

def main():
    print(arguements.value)
    print(arguements.url)
    printer(readResponse(sendUrl("https://www.google.ca")))

    
if __name__ == "__main__":
    argparser = argparse.ArgumentParser(prog="vtcli", description="CLI tool for virus scanning with Virus Total")

    argparser.add_argument("value", nargs=1, metavar="File")

    argparser.add_argument("-u", "--url", action="store_true", help="Scan url")

    argparser.add_argument("-d", "--directory", action="store_true", help="Scan directory")

    argparser.add_argument("-dc", "--directory-continue", action="store_true", help="Scan directory continue on error")

    argparser.add_argument("-c", "--continue", action="store_true", help="Continue on error, only useful with -d")

    argparser.add_argument("-f", "--file", action="store_true", help="Scan file, same as no flags")

    argparser.add_argument("-v", "--verbose", action="store_true", help="More output, better if you want to see specifics")

    argparser.add_argument("-r", "--raw", action="store_true", help="Raw output of json")

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

