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

if [ $1 = "start" ]; then
	echo "Starting MyVD..."
	
	export LOCAL_CLASSPATH="$MYVD_HOME/jar/myvd.jar:"
	for jarFile in `ls $MYVD_HOME/lib/*.jar`
	do
		export LOCAL_CLASSPATH="$jarFile:$LOCAL_CLASSPATH"
	done
	
	if [ -d $MYVD_HOME/qslib ]; then
		for jarFile in `ls $MYVD_HOME/qslib/*.jar`
		do
			export LOCAL_CLASSPATH="$jarFile:$LOCAL_CLASSPATH"
		done
	fi
	
	echo "Classpath : $LOCAL_CLASSPATH"

	
	export MYVD_CMD="$JAVA_CMD -server -Djavax.net.ssl.trustStore=$MYVD_HOME/conf/myvd-server.ks -Dderby.system.home=$MYVD_HOME/derbyHome net.sourceforge.myvd.server.Server $MYVD_HOME/conf/myvd.conf"
	

	
	$MYVD_HOME/bin/runserver.sh "$LOCAL_CLASSPATH" "$MYVD_HOME" "$MYVD_CMD" 2>&1 > /dev/null &
	
	
elif [ $1 = "stop" ]; then
	echo "Stopping MyVD..."
	export PID=`cat $MYVD_HOME/.myvdpid`
	kill $PID
fi
