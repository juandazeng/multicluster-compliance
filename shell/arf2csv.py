import csv
import argparse
import os
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

# Constants
BENCHMARK_ID = "xccdf_org.ssgproject.content_benchmark_OCP-4"
REFERENCE_HREF = "https://www.cisecurity.org/benchmark/kubernetes/"
SCAN_DATE_FORMAT = "%Y-%m-%d"
SCAN_TIME_FORMAT = "%H:%M:%S %z"
CSV_HEADER = [
    "Target Name",
    "End Time",
    "Platform Name",
    "Platform Release",
    "Environment",
    "Profile Name",
    "Profile Title",
    "Profile Version",
    "Profile Summary",
    "Control ID",
    "Control Title",
    "Impact",
    "Result Status"
]
SUMMARY_CSV_HEADER = [
    "Target Name",
    "End Time",
    "Platform Name",
    "Platform Release",
    "Environment",
    "Profile Name",
    "Profile Title",
    "Profile Version",
    "Profile Summary",
    "Pass Count",
    "Fail Count",
    "Not Applicable Count",
    "Not Checked Count"
]

# Main function
def main():
    # Initialize arguments parser
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--cluster", help="Cluster name", required=True)
    parser.add_argument("-e", "--environment", help="Environment name", default="")
    parser.add_argument("-t", "--target", help="Target type: cluster, master, worker", required=True, choices=["cluster", "master", "worker"])
    parser.add_argument("-i", "--input", help="Input ARF XML file name (full path)", required=True)
    arguments = parser.parse_args()

    clusterName = arguments.cluster
    targetEnvironment = arguments.environment
    targetType = arguments.target
    xmlFileName = arguments.input

    scanResultSummary = arf2csv(xmlFileName, targetType, clusterName, targetEnvironment)

    # Append the result summary into a summary CSV file
    summaryCsvFileName = clusterName + "/" + targetType + "/" + targetType + ".csv"
    isNewCsvFile = not os.path.exists(summaryCsvFileName)
    with open(summaryCsvFileName, "w" if isNewCsvFile else "a", newline="") as f:
        writer = csv.writer(f, dialect="excel")
        if isNewCsvFile:
            writer.writerow(SUMMARY_CSV_HEADER)
        
        writer.writerow([
            scanResultSummary.targetName,
            scanResultSummary.scanDateTime,
            scanResultSummary.platformName,
            scanResultSummary.platformRelease,
            scanResultSummary.targetEnvironment,
            scanResultSummary.profileName,
            scanResultSummary.profileTitle,
            scanResultSummary.profileVersion,
            scanResultSummary.profileSummary,
            scanResultSummary.passCount,
            scanResultSummary.failCount,
            scanResultSummary.notApplicableCount,
            scanResultSummary.notCheckedCount
        ])

class ScanResultSummary:
    targetType = ""
    targetName = ""
    targetEnvironment = ""
    scanDateTime = ""

    platformName = ""
    platformRelease = ""

    profileName = ""
    profileTitle = ""
    profileVersion = ""
    profileSummary = ""
    passCount = 0
    failCount = 0
    notApplicableCount = 0
    notCheckedCount = 0

# Convert an ARF XML file into a CSV file
# xmlFileName = full path to the ARF XML file
# targetType = ["cluster", "master", "worker"]. "cluster"=ocp4-cis profile; "master"/"worker"=ocp4-cis-node profile
# clusterName = only used if targetType is "cluster"
# The output csv file will be in the same directory as the input ARF XML file
# Returns a ScanResultSummary object
def arf2csv(xmlFileName, targetType, clusterName="", environment=""):
    scanResultSummary = ScanResultSummary()
    scanResultSummary.targetType = targetType
    scanResultSummary.targetEnvironment = environment

    csvFileName = Path(xmlFileName).with_suffix(".csv")

    xmlns = {
        "arf":"http://scap.nist.gov/schema/asset-reporting-format/1.1",
        "ds":"http://scap.nist.gov/schema/scap/source/1.2",
        "xccdf-1.2":"http://checklists.nist.gov/xccdf/1.2",
        "ind-sys":"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#independent",
        "":"http://checklists.nist.gov/xccdf/1.2"
    }

    try:
        xml = ET.parse(xmlFileName)

        xmlRoot = xml.getroot()

        # Find the benchmark that we want
        benchmarkElement = xmlRoot.find(f"./arf:report-requests/arf:report-request/arf:content/ds:data-stream-collection/ds:component/xccdf-1.2:Benchmark[@id='{BENCHMARK_ID}']", xmlns)

        # The rules are in the "./xccdf-1.2:Group[@id='xccdf_org.ssgproject.content_group_openshift']
        # But for simplicity we will just gather all rules here
        rules = {}
        ruleElements = benchmarkElement.findall(".//xccdf-1.2:Rule", xmlns)
        for ruleElement in ruleElements:
            id = ruleElement.attrib["id"]
            identElement = ruleElement.find("./xccdf-1.2:ident", xmlns)
            rules[id] = {
                "id":id,
                "ident": {"system":identElement.attrib["system"], "id":identElement.text} if identElement is not None else None,
                "severity":ruleElement.attrib["severity"],
                "title":ruleElement.find("./xccdf-1.2:title", xmlns).text,
                "description":ruleElement.find("./xccdf-1.2:description", xmlns).text,
                "rationale":ruleElement.find("./xccdf-1.2:rationale", xmlns).text
            }
            references = []
            referenceElements = ruleElement.findall("./xccdf-1.2:reference", xmlns)
            for referenceElement in referenceElements:
                referenceHref = referenceElement.attrib["href"]
                referenceId = referenceElement.text
                references.append({"href":referenceHref, "id":referenceId})
            rules[id]["references"] = references

        # Find the TestResult element
        testResultElement = xmlRoot.find("./arf:reports/arf:report[@id='xccdf1']/arf:content/{http://checklists.nist.gov/xccdf/1.2}TestResult", xmlns)

        # Only continue if it refers to the benchmark that we want
        if testResultElement.find("./{http://checklists.nist.gov/xccdf/1.2}benchmark", xmlns).attrib["id"] == BENCHMARK_ID:
            try:
                # Gather profile details
                scanResultSummary.profileName = testResultElement.find("./{http://checklists.nist.gov/xccdf/1.2}profile", xmlns).attrib["idref"]
                profileElement = benchmarkElement.find(f"./xccdf-1.2:Profile[@id='{scanResultSummary.profileName}']", xmlns)
                scanResultSummary.profileVersion = profileElement.find(f"./xccdf-1.2:version", xmlns).text
                scanResultSummary.profileTitle = profileElement.find(f"./xccdf-1.2:title", xmlns).text
                scanResultSummary.profileSummary = profileElement.find(f"./xccdf-1.2:description", xmlns).text

                # Gather platform details
                ovalResultsXmlns = "{http://oval.mitre.org/XMLSchema/oval-results-5}"
                ovalSystemCharacteristicsXmlns = "{http://oval.mitre.org/XMLSchema/oval-system-characteristics-5}"
                systemCharacteristicsElement = xmlRoot.find(f"./arf:reports/arf:report[@id='oval1']/arf:content/{ovalResultsXmlns}oval_results/{ovalResultsXmlns}results/{ovalResultsXmlns}system/{ovalSystemCharacteristicsXmlns}oval_system_characteristics", xmlns)
                if targetType == "cluster":
                    scanResultSummary.platformName = "OpenShift Container Platform"
                    scanResultSummary.platformRelease = systemCharacteristicsElement.find(f"./{ovalSystemCharacteristicsXmlns}system_data/ind-sys:yamlfilecontent_item[@id='1000087']/ind-sys:value[@datatype='record']/{ovalSystemCharacteristicsXmlns}field", xmlns).text
                else:
                    # Gather master/worker node details
                    systemInfoElement = systemCharacteristicsElement.find(f"./{ovalSystemCharacteristicsXmlns}system_info", xmlns)
                    scanResultSummary.platformName = systemInfoElement.find(f"./{ovalSystemCharacteristicsXmlns}os_name", xmlns).text
                    scanResultSummary.platformRelease = systemInfoElement.find(f"./{ovalSystemCharacteristicsXmlns}os_version", xmlns).text

                # Get the test result metadata
                scanResultSummary.scanDateTime = testResultElement.attrib["end-time"]
                scanResultSummary.targetName = clusterName if targetType == "cluster" else testResultElement.find("./{http://checklists.nist.gov/xccdf/1.2}target", xmlns).text
            except Exception as e:
                print(f"WARNING: {e}")

            # Keep results grouped by the specified REFERENCE_HREF
            resultsGroupedByReferenceId = {}
            ruleResultElements = testResultElement.findall("./{http://checklists.nist.gov/xccdf/1.2}rule-result", xmlns)
            for ruleResultElement in ruleResultElements:
                ruleId = ruleResultElement.attrib["idref"]
                if ruleId in rules:
                    rule = rules[ruleId]
                    result = ruleResultElement.find("./{http://checklists.nist.gov/xccdf/1.2}result", xmlns).text
                    
                    if result != "notselected":
                        # Get all IDs of REFERENCE_HREF in this rule
                        for reference in rule["references"]:
                            if reference["href"] == REFERENCE_HREF:
                                referenceId = reference["id"]
                                if referenceId not in resultsGroupedByReferenceId: resultsGroupedByReferenceId[referenceId] = []
                                resultsGroupedByReferenceId[referenceId].append({
                                    "rule":rule,
                                    "result":result
                                })

            with open(csvFileName, "w", newline="") as f:
                writer = csv.writer(f, dialect="excel")
                writer.writerow(CSV_HEADER)

                # Sort the results correctly based on 1.1.1 format
                for referenceId in sorted(resultsGroupedByReferenceId, key=lambda x: [int(i) for i in x.rstrip(".").split(".")]):
                    for result in resultsGroupedByReferenceId[referenceId]:
                        rule = result["rule"]
                        passOrFail = result["result"]
                        writer.writerow([
                            scanResultSummary.targetName,
                            scanResultSummary.scanDateTime,
                            scanResultSummary.platformName,
                            scanResultSummary.platformRelease,
                            scanResultSummary.targetEnvironment,
                            scanResultSummary.profileName,
                            scanResultSummary.profileTitle,
                            scanResultSummary.profileVersion,
                            scanResultSummary.profileSummary,
                            referenceId + "_" + rule["id"],
                            rule["title"],
                            rule["severity"],
                            passOrFail
                        ])

                        # Count the number of passes and failures
                        if passOrFail.lower() == "pass":
                            scanResultSummary.passCount += 1
                        elif passOrFail.lower() == "fail":
                            scanResultSummary.failCount += 1
                        elif passOrFail.lower() == "notapplicable":
                            scanResultSummary.notApplicableCount += 1
                        elif passOrFail.lower() == "notchecked":
                            scanResultSummary.notCheckedCount += 1
            
            print(f"Successfully generated {csvFileName}\n")

        return scanResultSummary

    except Exception as e:
        print("Error, unable to parse XML document.  Are you sure that's ARF?")
        raise e 


if __name__=="__main__": 
    main() 