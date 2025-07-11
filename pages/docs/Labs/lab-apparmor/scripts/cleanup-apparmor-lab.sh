#!/bin/bash

echo "Cleaning up AppArmor lab environment..."

# Stop and remove containers
docker stop $(docker ps -aq --filter "name=nginx-") 2>/dev/null || true
docker rm $(docker ps -aq --filter "name=nginx-") 2>/dev/null || true

# Remove test files
rm -f /tmp/nginx-test/nginx.conf
rmdir /tmp/nginx-test 2>/dev/null || true
rm -f /tmp/test-capabilities.sh
rm -f /tmp/apparmor-violations.log

# Remove scripts
rm -f /tmp/monitor-apparmor.sh
rm -f /tmp/deploy-apparmor-profiles.sh
rm -f /tmp/validate-apparmor-profiles.sh
rm -f /tmp/debug-apparmor.sh

# Note: AppArmor profiles are left in place for future use
# To remove them manually:
# sudo apparmor_parser -R /etc/apparmor.d/docker-nginx-restrictive
# sudo apparmor_parser -R /etc/apparmor.d/docker-nginx-logging
# sudo rm /etc/apparmor.d/docker-nginx-*

echo "Cleanup completed."
echo "AppArmor profiles are still loaded. Use 'sudo aa-status' to check."
