#!/bin/sh

fn1() {
    ignores="^ssh"
    hostname=`hostname`
    IFS="
"
    for pid in `lsof -n -iTCP |sed 1d | egrep -v "$ignores" | awk '{print $2}' | sort | uniq | grep .` ; do
        cat /proc/$pid/cmdline | sed s/^/$pid:cmdline:/g && echo
        cat /proc/$pid/environ | sed s/^/$pid:environ:/g && echo
        lsof -a -n -iTCP -P -p $pid | sed 1d | sed -r 's/^.* TCP (.*)/'$pid':tcp_conns:\1/g'
        ps -ouser,etime,command -p $pid | sed 1d | sed 's/^/'$pid':process:/g'
        stat -c%N /proc/$pid/exe | sed 's/^/'$pid':stat:/g'
    done | sed 's/| sed s/^/$HOSTNAME:/g
}

ssh localhost "`typeset -f`;fn1"
