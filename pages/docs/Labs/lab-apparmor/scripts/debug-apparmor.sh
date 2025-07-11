#!/bin/bash

echo "=== AppArmor Debug Information ==="

echo "1. AppArmor Status:"
sudo aa-status

echo -e "\n2. Loaded Docker Profiles:"
sudo aa-status | grep docker

echo -e "\n3. Recent AppArmor Messages:"
sudo journalctl --since "1 hour ago" | grep -i apparmor | tail -10

echo -e "\n4. Docker Info:"
docker info | grep -i apparmor

echo -e "\n5. Running Containers with AppArmor:"
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | head -1
for container in $(docker ps -q); do
    name=$(docker inspect $container --format '{{.Name}}' | sed 's/\///')
    image=$(docker inspect $container --format '{{.Config.Image}}')
    apparmor=$(docker inspect $container --format '{{range .HostConfig.SecurityOpt}}{{.}}{{end}}' | grep apparmor || echo "default")
    echo "$name	$image	$apparmor"
done

echo -e "\n6. Profile Files:"
ls -la /etc/apparmor.d/docker-* 2>/dev/null || echo "No docker profiles found"

echo -e "\n7. Profile Syntax Check:"
for profile in /etc/apparmor.d/docker-*; do
    if [ -f "$profile" ]; then
        echo -n "$(basename $profile): "
        if sudo apparmor_parser -Q "$profile" >/dev/null 2>&1; then
            echo "OK"
        else
            echo "SYNTAX ERROR"
        fi
    fi
done

echo -e "\nDebug information collected."
