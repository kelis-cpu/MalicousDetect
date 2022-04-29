#!/bin/bash

DIR="$( cd "$( dirname "$0"  )" && pwd  )"
#cd $DIR

filename=$1
run_mode=debug
detect_timeout=10
memory_limit=500
PYTHON_EXE=$DIR/bin/python3

if [ -n "$filename" ];then
	cmd_1="$PYTHON_EXE -D enable=true,jump_branch=false,run_mode=${run_mode},detect_timeout=${detect_timeout},memory_limit=${memory_limit} $filename"
	cmd_2="$PYTHON_EXE -D enable=true,jump_branch=true,run_mode=${run_mode},detect_timeout=${detect_timeout},memory_limit=${memory_limit} $filename"

	t=True
	rs=`eval $cmd_1 | grep 'Malicious'`
	res=`echo $rs | sed 's/,/\n/g'| grep 'Malicious'|sed "s/'//g"|sed 's/}//'`
	if [ -n "$res" ];then
		final=${res#*:}
		if [ $final=$t ];then
			echo $rs
		else
			rs=`eval $cmd_2 | grep 'Malicious'`
			echo $rs
		fi
	else
		rs=`eval $cmd_2 | grep 'Malicious'`
		echo $rs
	fi
else
	echo "please input filepath"
fi
