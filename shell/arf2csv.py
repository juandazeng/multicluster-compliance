import csv
import argparse
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

# Constants
BENCHMARK_ID = "xccdf_org.ssgproject.content_benchmark_OCP-4"
REFERENCE_HREF = "https://www.cisecurity.org/benchmark/kubernetes/"
SCAN_DATE_FORMAT = "%Y-%m-%d"
SCAN_TIME_FORMAT = "%H:%M:%S %z"
CSV_HEADER = ["Scan Date", "Scan Time", "Target Type", "Target Name", "Number", "Rule", "Severity", "Result"]
SUMMARY_CSV_HEADER = ["Scan Date", "Scan Time", "Target Type", "Target Name", "Pass Count", "Fail Count"]

# Main function
def main():
    # Initialize arguments parser
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--cluster", help="Cluster name", required=True)
    parser.add_argument("-t", "--target", help="Target type: cluster, master, worker", required=True, choices=["cluster", "master", "worker"])
    parser.add_argument("-i", "--input", help="Input ARF XML file name (full path)", required=True)
    arguments = parser.parse_args()

    clusterName = arguments.cluster
    targetType = arguments.target
    xmlFileName = arguments.input

    scanResultSummary = arf2csv(xmlFileName, targetType, clusterName)

    # Append the result summary into a summary CSV file
    summaryCsvFileName = targetType + "/" + targetType + ".csv"
    with open(summaryCsvFileName, "a", newline="") as f:
        writer = csv.writer(f, dialect="excel")
        writer.writerow(SUMMARY_CSV_HEADER)
        writer.writerow([
            scanResultSummary.scanDate,
            scanResultSummary.scanTime,
            scanResultSummary.targetType,
            scanResultSummary.targetName,
            scanResultSummary.passCount,
            scanResultSummary.failCount
        ])

class ScanResultSummary:
    scanDate = ""
    scanTime = ""
    targetType = ""
    targetName = ""
    passCount = 0
    failCount = 0

# Convert an ARF XML file into a CSV file
# xmlFileName = full path to the ARF XML file
# targetType = ["cluster", "master", "worker"]. "cluster"=ocp4-cis profile; "master"/"worker"=ocp4-cis-node profile
# clusterName = only used if targetType is "cluster"
# The output csv file will be in the same directory as the input ARF XML file
# Returns a ScanResultSummary object
def arf2csv(xmlFileName, targetType, clusterName=""):
    scanResultSummary = ScanResultSummary()
    scanResultSummary.targetType = targetType

    csvFileName = Path(xmlFileName).with_suffix(".csv")

    xmlns = {
        "arf":"http://scap.nist.gov/schema/asset-reporting-format/1.1",
        "ds":"http://scap.nist.gov/schema/scap/source/1.2",
        "xccdf-1.2":"http://checklists.nist.gov/xccdf/1.2",
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
        testResultElement = xmlRoot.find("./arf:reports/arf:report/arf:content/{http://checklists.nist.gov/xccdf/1.2}TestResult", xmlns)

        # Only continue if it refers to the benchmark that we want
        if testResultElement.find("./{http://checklists.nist.gov/xccdf/1.2}benchmark", xmlns).attrib["id"] == BENCHMARK_ID:
            # Get the test result metadata
            scanDateTimeIso = testResultElement.attrib["start-time"]
            scanResultSummary.targetName = clusterName if targetType == "cluster" else testResultElement.find("./{http://checklists.nist.gov/xccdf/1.2}target", xmlns).text

            # Parse the scan date and time from ISO format
            try:
                scanDateTimeLocal = datetime.fromisoformat(scanDateTimeIso).astimezone()
                scanResultSummary.scanDate = scanDateTimeLocal.strftime(SCAN_DATE_FORMAT)
                scanResultSummary.scanTime = scanDateTimeLocal.strftime(SCAN_TIME_FORMAT)
            except:
                pass

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
                            scanResultSummary.scanDate,
                            scanResultSummary.scanTime,
                            scanResultSummary.targetType,
                            scanResultSummary.targetName,
                            referenceId,
                            rule["title"],
                            rule["severity"],
                            passOrFail
                        ])

                        # Count the number of passes and failures
                        if passOrFail.lower() == "pass":
                            scanResultSummary.passCount += 1
                        elif passOrFail.lower() == "fail":
                            scanResultSummary.failCount += 1
            
            print(f"Successfully generated {csvFileName}\n")

        return scanResultSummary

    except Exception as e:
        print("Error, unable to parse XML document.  Are you sure that's ARF?")
        raise e 


if __name__=="__main__": 
    main() 