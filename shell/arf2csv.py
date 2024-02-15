import csv
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

# Constants
BENCHMARK_ID = "xccdf_org.ssgproject.content_benchmark_OCP-4"
REFERENCE_HREF = "https://www.cisecurity.org/benchmark/kubernetes/"
CSV_HEADER = ["Number", "Rule", "Severity", "Result"]

if len(sys.argv) < 2:
    print("Needs at least 1 parameter: input ARF xml file(s). It will output a csv file with the same name as the input file.")
    print("Usage example: python arf2csv.py input1.xml")
    sys.exit(0)

for xmlFileName in sys.argv[1:]:
    print(f"Processing {xmlFileName}")
    csvFileName = Path(xmlFileName).with_suffix(".csv")

    xmlns = {
        "arf":"http://scap.nist.gov/schema/asset-reporting-format/1.1",
        "ds":"http://scap.nist.gov/schema/scap/source/1.2",
        "xccdf-1.2":"http://checklists.nist.gov/xccdf/1.2",
        "":"http://checklists.nist.gov/xccdf/1.2"
    }

    try:
        xml = ET.parse(xmlFileName)
    except Exception as e:
        print("Error, unable to parse XML document.  Are you sure that's ARF?")
        sys.exit(-1)

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
                    writer.writerow([referenceId, rule["title"], rule["severity"], result["result"]])
        
        print(f"Successfully generated {csvFileName}\n")

