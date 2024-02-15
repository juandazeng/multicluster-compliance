echo ---------------------------------------------- 
echo Coverting and copying results...
echo ----------------------------------------------
clusterName=$1
splunkToken=$2
splunkUrlTemplate=$3
csvFile=1234.csv
# curl -D - -H "Authorization: Bearer $SPLUNK_TOKEN" -F 'data=@my-datafile-20210832.csv' “https://splunk.mydomain.com:8089/services/receivers/stream?sourcetype=mycustomcsv&index=mycustomindex&host=curl-testing”
splunkUploadCommand=$(sed -e "$splunkUrlTemplate/#splunk_token/$splunkToken/g" -e "$splunkUrlTemplate/#csv_file/$csvFile/g")

echo $clusterName
echo $splunkToken
echo $splunkUploadCommand

for d in $(ls | egrep -i '[0-9]')
do
  echo $d
  bzip2FileCount=`ls -1 $d/*.bzip2 2>/dev/null | wc -l`
  if [ $bzip2FileCount -gt 0 ]
  then 
    for f in $d/*.bzip2
    do
      localNameExt=$(basename $f)
      localName=${localNameExt%.*}
      targetName=$d-$localName
      echo $targetName
      bunzip2 -c $f > $targetName.xml
      # oscap xccdf generate report $targetName.xml > $targetName.html
      python3 ../shell/arf2csv.py $targetName.xml
    done
  fi
  rm -rf $d
done
resultsDir=../results
mkdir -p "$resultsDir/xml"
mkdir -p "$resultsDir/html"
mkdir -p "$resultsDir/csv"
cp *.xml "$resultsDir/xml/"
cp *.html "$resultsDir/html/"
cp *.csv "$resultsDir/csv/"
rm -f *.xml *.html *.csv

echo
echo ---------------------------------------------- 
echo Done.
echo ---------------------------------------------- 




