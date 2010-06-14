#!/bin/sh
echo "del.sh: $1 $2 $3" >> scriptlog

IP=$1
MAC=$2
CLASS=$3

/sbin/iptables -t nat -D vrauth -s $IP -m mac --mac-source $MAC -j vrauth-ok 2>/dev/null
/sbin/iptables -D vrauth -s $IP -m mac --mac-source $MAC -j ACCEPT 2>/dev/null

#/sbin/iptables -D vrauth2 -s $IP -m mac --mac-source $MAC -j ACCEPT 2>/dev/null
