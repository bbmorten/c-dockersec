#!/bin/bash

PROFILE_DIR="/etc/apparmor.d"
PROFILES=(
    "docker-nginx-restrictive"
    "docker-webapp"
    "docker-database"
)

echo "Deploying AppArmor profiles..."

for profile in "${PROFILES[@]}"; do
    if [ -f "$PROFILE_DIR/$profile" ]; then
        echo "Loading profile: $profile"
        sudo apparmor_parser -r "$PROFILE_DIR/$profile"
        if [ $? -eq 0 ]; then
            echo "✓ Profile $profile loaded successfully"
        else
            echo "✗ Failed to load profile $profile"
        fi
    else
        echo "✗ Profile file not found: $PROFILE_DIR/$profile"
    fi
done

echo "Profile deployment completed."
sudo aa-status | grep docker
