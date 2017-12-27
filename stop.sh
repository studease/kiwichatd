#!/bin/bash

pids=$(ps x | grep kiwichatd | grep -v grep | awk '{print $1}')
for pid in $pids; do
	echo "Killing kiwichatd process ${pid}..."
	kill -9 $pid
done

