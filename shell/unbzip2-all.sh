echo ---------------------------------------------- 
echo Unzipping bzip2 files...
echo ----------------------------------------------

clusterName=$1
category=$2
getAllResultsDirectories=`ls $category/ | egrep -i '[0-9]'`
for numberedDirectory in $getAllResultsDirectories
do
  targetDirectory=$category/$numberedDirectory
  bzip2FileCount=`ls -1 $targetDirectory/*.bzip2 2>/dev/null | wc -l`
  if [ $bzip2FileCount -gt 0 ]
  then
    for f in $targetDirectory/*.bzip2
    do
      localNameExt=$(basename $f)
      localName=$numberedDirectory-${localNameExt%.*}
      targetName=$category/$localName
      targetNameXml=$targetName.xml
      echo source:$f
      echo target:$targetNameXml
      bunzip2 -c $f > $targetNameXml
      # oscap xccdf generate report $targetName.xml > $targetName.html
      python3 ../shell/arf2csv.py --cluster $clusterName --target $category --input $targetNameXml
      rm $targetNameXml
    done
  fi
  rm -rf $targetDirectory
done
rm -rf $category/lost+found

echo
echo ---------------------------------------------- 
echo Done.
echo ---------------------------------------------- 




