echo
echo ----------------------------------------------
echo Creating pv-extract pod...
echo ---------------------------------------------- 
cat << EOF | oc create -n openshift-compliance -f -
apiVersion: "v1"
kind: Pod
metadata:
  name: pv-extract
spec:
  containers:
    - name: pv-extract-pod
      image: registry.access.redhat.com/ubi8/ubi
      command: ["sleep", "3000"]
      volumeMounts:
      - mountPath: "/ocp4-cis"
        name: ocp4-cis-vol
      - mountPath: "/ocp4-cis-node-master"
        name: ocp4-cis-node-master-vol
  volumes:
    - name: ocp4-cis-vol
      persistentVolumeClaim:
        claimName: ocp4-cis
    - name: ocp4-cis-node-master-vol
      persistentVolumeClaim:
        claimName: ocp4-cis-node-master
EOF

echo
echo ---------------------------------------------- 
echo Waiting for pv-extract pod to be ready...
echo ---------------------------------------------- 
until
  oc get pod pv-extract -n openshift-compliance | grep -m 1 "Running"
do
  sleep 2
done

echo
echo ---------------------------------------------- 
echo Copying scan results...
echo ---------------------------------------------- 
oc cp pv-extract:/ocp4-cis -n openshift-compliance .
oc cp pv-extract:/ocp4-cis-node-master -n openshift-compliance .

echo
echo ---------------------------------------------- 
echo Coverting and copying results...
echo ---------------------------------------------- 
for d in $(ls | egrep -i '[0-9]')
do
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
      oscap xccdf generate report $targetName.xml > $targetName.html
    done
  fi
  rm -rf $d
done
resultsDir=/media/sf_Downloads/results
mkdir -p "$resultsDir/xml"
mkdir -p "$resultsDir/html"
cp *.xml "$resultsDir/xml/"
cp *.html "$resultsDir/html/"
rm -f *.xml *.html

echo
echo ---------------------------------------------- 
echo Deleting pv-extract pod...
echo ---------------------------------------------- 
oc delete pod pv-extract -n openshift-compliance

echo
echo ---------------------------------------------- 
echo Done.
echo ---------------------------------------------- 




