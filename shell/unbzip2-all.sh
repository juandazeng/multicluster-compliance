echo ---------------------------------------------- 
echo Unzipping bzip2 files...
echo ----------------------------------------------

category=$1
echo category:$category
getAllResultsDirectories=`ls $category/ | egrep -i '[0-9]'`
for d in $getAllResultsDirectories
do
  d=$category/$d
  echo directory:$d
  bzip2FileCount=`ls -1 $d/*.bzip2 2>/dev/null | wc -l`
  echo count:$bzip2FileCount
  if [ $bzip2FileCount -gt 0 ]
  then
    for f in $d/*.bzip2
    do
      localNameExt=$(basename $f)
      localName=${localNameExt%.*}
      targetName=$d-$localName
      echo targetName:$targetName
      bunzip2 -c $f > $targetName.xml
      # oscap xccdf generate report $targetName.xml > $targetName.html
      # python3 ../shell/arf2csv.py $targetName.xml
    done
  fi
  rm -rf $d
done

echo
echo ---------------------------------------------- 
echo Done.
echo ---------------------------------------------- 




