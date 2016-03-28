#!/bin/bash

export CLASSPATH=$1
export MYVD_HOME=$2
export MYVD_CMD=$3

echo $$ > $MYVD_HOME/.myvdpid

exec $MYVD_CMD