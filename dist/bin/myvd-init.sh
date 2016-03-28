#!/bin/bash

. /etc/rc.d/init.d/functions

export CONFIG_FILE=
export LOCAL_CP=
export INSTALL_DIR=

for jarFile in `ls $INSTALL_DIR/lib`
do
	export LOCAL_CP="$INSTALL_DIR/lib/$jarFile:$LOCAL_CP"
done

export CLASSPATH=$LOCAL_CP

MYVD="java -server net.sourceforge.myvd.server.Server $CONFIG_FILE"

case "$1" in
	"start")
		echo -n "Starting MYVD......"
		daemon $MYVD
		exit $?
	;;
	
	"stop")
		echo "stopped....."
	;;
esac