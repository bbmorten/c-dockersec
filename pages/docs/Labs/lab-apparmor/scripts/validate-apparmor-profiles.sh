#!/bin/bash

echo "Validating AppArmor profiles..."

# Check if AppArmor is enabled
if ! sudo aa-status >/dev/null 2>&1; then
    echo "✗ AppArmor is not running"
    exit 1
fi

# Test profile syntax
PROFILES="/etc/apparmor.d/docker-*"
for profile in $PROFILES; do
    if [ -f "$profile" ]; then
        echo "Checking syntax: $(basename $profile)"
        if sudo apparmor_parser -Q "$profile" >/dev/null 2>&1; then
            echo "✓ Syntax OK: $(basename $profile)"
        else
            echo "✗ Syntax error: $(basename $profile)"
        fi
    fi
done

# Test with actual containers
echo "Testing profiles with containers..."

# Test nginx profile
docker run --rm -d \
    --name test-nginx \
    --security-opt apparmor=docker-nginx-restrictive \
    nginx:alpine >/dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✓ nginx profile works"
    docker stop test-nginx >/dev/null 2>&1
else
    echo "✗ nginx profile failed"
fi

echo "Validation completed."
