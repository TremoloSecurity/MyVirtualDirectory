#!/bin/bash


#First see where java is
echo "Java home : $JAVA_HOME"

if [ ! -z $JAVA_HOME ]; then
	export JAVA_CMD="$JAVA_HOME/bin/java"
else
	JAVA_CMD=`which java`
fi 

#determine where $MYVD_HOME is

if [ -z $MYVD_HOME ]; then
	export MYVD_HOME="$(cd ..;pwd)"
fi

echo "MyVD Home : $MYVD_HOME"


echo "Starting MyVD..."

export LOCAL_CLASSPATH="$MYVD_HOME/jar/myvd.jar:$MYVD_HOME/jar/myvd-test.jar:"
for jarFile in `ls $MYVD_HOME/lib/*.jar`
do
	export LOCAL_CLASSPATH="$jarFile:$LOCAL_CLASSPATH"
done

for jarFile in `ls $MYVD_HOME/qslib/*.jar`
do
	export LOCAL_CLASSPATH="$jarFile:$LOCAL_CLASSPATH"
done

echo "Classpath : $LOCAL_CLASSPATH"

export CLASSPATH=$LOCAL_CLASSPATH
export MYVD_CMD="$JAVA_CMD -server -Djavax.net.ssl.trustStore=$MYVD_HOME/conf/myvd-server.ks -Dderby.system.home=$MYVD_HOME/derbyHome net.sourceforge.myvd.quickstart.$1 $MYVD_HOME"

exec $MYVD_CMD


	
	
