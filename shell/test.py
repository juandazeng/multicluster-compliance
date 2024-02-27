import arf2csv

# Cluster file test
arf2csv.arf2csv(
    xmlFileName=r"c:\Users\juanda\Downloads\c1.xml",
    targetType="cluster",
    clusterName="my-cluster",
    environment="uat"
)

# Master file test
arf2csv.arf2csv(
    xmlFileName=r"c:\Users\juanda\Downloads\m1.xml",
    targetType="master",
    environment="uat"
)

# Worker file test
arf2csv.arf2csv(
    xmlFileName=r"c:\Users\juanda\Downloads\2.xml",
    targetType="worker",
    environment="uat"
)