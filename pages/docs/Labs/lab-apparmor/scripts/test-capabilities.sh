#!/bin/bash

echo "Testing capabilities..."

# Test setuid capability
echo "Testing setuid..."
su - root -c "echo 'setuid test'" 2>&1 || echo "setuid blocked"

# Test mount capability
echo "Testing mount..."
mount -t tmpfs none /tmp/test 2>&1 || echo "mount blocked"

# Test module loading
echo "Testing module loading..."
modprobe dummy 2>&1 || echo "module loading blocked"

# Test time setting
echo "Testing time setting..."
date -s "2024-01-01" 2>&1 || echo "time setting blocked"
