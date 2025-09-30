
import csv
import argparse
import json
import ssl
from urllib.request import urlopen, Request

# Prepare for API calls
rhacsCentralUrl: str = ""
rhacsApiToken: str = ""
outputFileName: str = ""
authorizationHeader = None
requestContext = ssl.create_default_context()
requestContext.check_hostname = False
requestContext.verify_mode = ssl.CERT_NONE

def main():
    # We will modify these global variables
    global rhacsCentralUrl, rhacsApiToken, outputFileName, apiHeader
    
    # Initialize arguments parser
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", "--url", help="RHACS CENTRAL URL, e.g. https://central-stackrox.apps.myocpcluster.com", required=True)
    parser.add_argument("-t", "--token", help="RHACS API token", required=True)
    parser.add_argument("-o", "--output", help="Output CSV file name", required=True)
    parser.add_argument("-f", "--format", help="Output format (either csv or json)", choices=["csv", "json"], default="csv")
    arguments = parser.parse_args()
    
    rhacsCentralUrl = arguments.url
    rhacsApiToken = arguments.token
    outputFileName = arguments.output
    outputFormat = arguments.format

    # Prepare for API calls
    apiHeader = {
        "Authorization": "Bearer " + rhacsApiToken,
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": 0,
        "Accept": "application/json"
    }

    responseJson = getJsonFromRhacsApiV2("/compliance/scan/results/test1")
    if responseJson is not None:
        # Process the response here
        print(responseJson)
        ...
    
def getJsonFromRhacsApiV2(requestPath: str) -> dict | None:
    url=rhacsCentralUrl + "/v2" + requestPath
    apiHeader["Content-Length"] = 0
    with urlopen(Request(
        url=url,
        headers=apiHeader),
        context=requestContext) as response:
        if response.status != 200:
            print(f"Error: {response.status} - {response.msg} for request:{url}")
            return None
        else:
            return json.loads(response.read())

if __name__=="__main__": 
    main()