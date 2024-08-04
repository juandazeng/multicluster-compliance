import csv
import argparse
import json
import ssl
import re
from string import Template
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from datetime import datetime

# Constants
CSV_HEADER = [
    "Cluster Name",
    "Environment",
    "Cluster Descriptor",
    "Node Name",
    "Node Roles"
]

# The cluster regex matches the following:
# ocps4 - uat_abc_def123 <-- cluster name: ocps4, environment: uat, cluster descriptor: abc_def123
# ocps4 - uat            <-- cluster name: ocps4, environment: uat
# ocps4                  <-- cluster name: ocps4
CLUSTER_INFO_REGEX = r"([^\W_]+)(?:[\W_]+([^\W_]+)(?:[\W_]+(.*))?)?$"

NODE_ROLE_LABEL_PREFIX = "node-role.kubernetes.io/"

# Prepare for API calls
rhacsCentralUrl = None
rhacsApiToken = None
outputFileName = None
authorizationHeader = None
requestContext = ssl.create_default_context()
requestContext.check_hostname = False
requestContext.verify_mode = ssl.CERT_NONE

class ClusterDetail:
    def __init__(self) -> None:
        self.clusterId = ""
        self.clusterName = ""
        self.clusterEnvironment = ""
        self.clusterDescriptor = ""
        self.nodeDetails = {}
    
class NodeDetail:
    def __init__(self) -> None:
        self.nodeId = ""
        self.nodeName = ""
        self.nodeRoles = {}

# Main function
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

    responseJson = getJsonFromRhacsApi("/clusters")
    if responseJson is not None:
        # Create the CSV file
        with open(outputFileName, "w", newline="") as f:
            writer = csv.writer(f, dialect="excel")
            writer.writerow(CSV_HEADER)

            # Process all clusters
            clusters = responseJson["clusters"]
            for cluster in clusters:
                clusterId = cluster["id"]
                clusterName = cluster["name"]
                clusterEnvironment = ""
                clusterDescriptor = ""

                print(f"Inspecting nodes in cluster:{clusterName}...")

                # Try to parse cluster info
                try:
                    regexResult = re.search(CLUSTER_INFO_REGEX, clusterName)
                    if regexResult.group(1) is not None:
                        clusterName = regexResult.group(1)
                    if regexResult.group(2) is not None:
                        clusterEnvironment = regexResult.group(2)
                    if regexResult.group(3) is not None:
                        clusterDescriptor = regexResult.group(3)
                except:
                    pass

                # Process all nodes in this cluster
                responseJson = getJsonFromRhacsApi("/nodes/" + clusterId)
                nodes = responseJson["nodes"]
                nodeCount = len(nodes)
                currentNodeIndex = 0
                for node in nodes:
                    nodeId = node["id"]
                    nodeName = node["name"]
 
                    currentNodeIndex += 1
                    print(f"{currentNodeIndex} of {nodeCount} - Inspecting {clusterName}/{nodeName}...")

                    # Get the labels
                    for label in node["labels"]:
                        # If this is a node role
                        if label.startswith(NODE_ROLE_LABEL_PREFIX):
                            nodeRole = label[len(NODE_ROLE_LABEL_PREFIX):]




                            

                    try:
                        operationName = "getNodeNODE_CVE"
                        graphQlRequest = GRAPHQL_REQUEST_TEMPLATE.substitute(
                            operationName = operationName,
                            clusterId = clusterId,
                            nodeId = nodeId
                        ).replace("\n", "")

                        responseJson = getJsonFromRhacsGraphQl(operationName, graphQlRequest)
                        if responseJson is not None:
                            cves = responseJson["data"]["result"]["nodeVulnerabilities"]

                            for cve in cves:
                                # Add to the list of CVEs if it has not been added
                                cveId = cve["cve"]
                                if cveId not in currentClusterDetail.cveDetails:
                                    currentClusterDetail.cveDetails[cveId] = CveDetail()

                                currentCveDetail = currentClusterDetail.cveDetails[cveId]
                                
                                currentCveDetail.cve = cve
                                if nodeName not in currentCveDetail.nodes:
                                    currentCveDetail.nodes.append(nodeName)

                    except Exception as ex:
                        print(f"Not completing {clusterName}/{nodeName} due to ERROR:{type(ex)=}:{ex=}.")

        # Create the CSV file
        with open(outputFileName, "w", newline="", encoding="utf-8") as f:
            writer = None
            if (outputFormat == "csv"):
                writer = csv.writer(f, dialect="excel")
                writer.writerow(CSV_HEADER)

            # Sort the CVEs by environment, cluster name, and CVSS score
            sortedByClusterEnvironmentAndName = sorted(cvesByCluster,  key = lambda clusterId : (cvesByCluster[clusterId].clusterEnvironment, cvesByCluster[clusterId].clusterName))
            for clusterId in sortedByClusterEnvironmentAndName:
                clusterDetail = cvesByCluster[clusterId]

                for cveId in clusterDetail.cveDetails:
                    cveDetail = clusterDetail.cveDetails[cveId]
                    cveData = cveDetail.cve

                    # Parse the severity
                    severity = ""
                    try:
                        severity = VULNERABILITY_SEVERITY[cveData["severity"]]
                    except:
                        pass

                    if outputFormat == "csv":
                        outputRow = [
                            clusterDetail.clusterName,
                            clusterDetail.clusterEnvironment,
                            clusterDetail.clusterDescriptor,
                            cveId,
                            "Fixable" if cveData["isFixable"] else "Not Fixable",
                            severity,
                            "{0:.1f}".format(cveData["cvss"]),
                            "{0:.0f}%".format(cveData["envImpact"]*100),
                            "{0:.2f}".format(cveData["impactScore"]),
                            "\n".join(cveDetail.nodes),
                            cveData["publishedOn"] if cveData["publishedOn"] is not None else "",
                            cveData["createdAt"],
                            cveData["link"],
                            cveData["summary"]
                        ]
                        writer.writerow(outputRow)
                    elif outputFormat == "json":
                        outputRow = {
                            "clusterName": clusterDetail.clusterName,
                            "clusterEnvironment": clusterDetail.clusterEnvironment,
                            "clusterDescriptor": clusterDetail.clusterDescriptor,
                            "cve": cveId,
                            "fixable": "Fixable" if cveData["isFixable"] else "Not Fixable",
                            "severity": severity,
                            "cvss": "{0:.1f}".format(cveData["cvss"]),
                            "envImpact": "{0:.0f}%".format(cveData["envImpact"]*100),
                            "impactScore": "{0:.2f}".format(cveData["impactScore"]),
                            "nodes": "\n".join(cveDetail.nodes),
                            "publishedOn": cveData["publishedOn"] if cveData["publishedOn"] is not None else "",
                            "createdAt": cveData["createdAt"],
                            "link": cveData["link"],
                            "summary": cveData["summary"]
                        }
                        json.dump(outputRow, f, ensure_ascii=False)
                    f.flush()

        print(f"Successfully generated {outputFileName}\n")
                    
def getJsonFromRhacsApi(requestPath):
    url=rhacsCentralUrl + "/v1" + requestPath
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