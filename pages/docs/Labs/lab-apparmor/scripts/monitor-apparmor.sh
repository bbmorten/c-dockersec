#!/bin/bash

echo "Monitoring seccomp violations..."
echo "Press Ctrl+C to stop"

# Create log file
LOGFILE="/tmp/apparmor-violations.log"
echo "$(date): AppArmor monitoring started" >> $LOGFILE

# Monitor syslog for AppArmor violations
sudo tail -f /var/log/syslog | while read line; do
    if echo "$line" | grep -qi "apparmor.*denied"; then
        echo "$(date): APPARMOR VIOLATION - $line"
        echo "$(date): APPARMOR VIOLATION - $line" >> $LOGFILE
    fi
done
