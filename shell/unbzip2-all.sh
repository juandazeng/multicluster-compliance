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
      echo source:$f
      echo target:$targetName.xml
      bunzip2 -c $f > $targetName.xml
      # oscap xccdf generate report $targetName.xml > $targetName.html
      python3 ../shell/arf2csv.py --cluster $clusterName --target $category --input $localName.xml
    done
  fi
  rm -rf $d
done

echo
echo ---------------------------------------------- 
echo Done.
echo ---------------------------------------------- 




