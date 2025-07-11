# AppArmor Lab for Docker Security

This lab provides comprehensive hands-on experience with AppArmor security for Docker containers running on Ubuntu 24.04.

## Lab Structure

```
lab-apparmor/
├── index.mdx                    # Main lab documentation
├── README.md                    # This file
├── profiles/                    # AppArmor profile definitions
│   ├── docker-nginx-restrictive # Restrictive nginx profile
│   ├── docker-nginx-logging     # Logging nginx profile
│   └── docker-webapp           # Web application profile
├── abstractions/               # Reusable profile components
│   └── docker-base             # Base restrictions for containers
├── scripts/                    # Utility scripts
│   ├── monitor-apparmor.sh     # Real-time violation monitoring
│   ├── deploy-apparmor-profiles.sh # Profile deployment automation
│   ├── validate-apparmor-profiles.sh # Profile validation
│   ├── debug-apparmor.sh       # Debug information collection
│   ├── test-capabilities.sh    # Capability testing script
│   └── cleanup-apparmor-lab.sh # Environment cleanup
└── examples/                   # Configuration examples
    ├── docker-compose.yml      # Production-ready compose file
    └── nginx.conf              # Sample nginx configuration
```

## Getting Started

1. **Navigate to the lab**: Access the main lab content via `index.mdx`
2. **Follow the prerequisites**: Ensure Ubuntu 24.04 with Docker installed
3. **Work through sections**: Complete parts 1-12 sequentially
4. **Use provided files**: Copy profiles and scripts as instructed

## Key Features

### 🛡️ **Security Profiles**
- **Restrictive profiles** that block dangerous operations
- **Logging profiles** for monitoring and development
- **Parameterized profiles** with variables for flexibility

### 🔧 **Automation Scripts**
- **Deployment automation** for profile management
- **Validation tools** for testing profile syntax
- **Monitoring solutions** for real-time violation tracking

### 📚 **Comprehensive Coverage**
- Installation and setup verification
- Profile creation and customization
- Testing and validation procedures
- Production deployment strategies
- Troubleshooting and debugging

### 🎯 **Practical Exercises**
- Hands-on container security testing
- Real-world violation scenarios
- Profile optimization techniques
- Integration with other security tools

## Usage Instructions

### Copy Profiles to System
```bash
# Copy profiles to AppArmor directory
sudo cp profiles/* /etc/apparmor.d/

# Copy abstractions
sudo cp abstractions/* /etc/apparmor.d/abstractions/

# Load profiles
sudo apparmor_parser -r /etc/apparmor.d/docker-nginx-restrictive
```

### Run Scripts
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Run monitoring
./scripts/monitor-apparmor.sh

# Deploy profiles
./scripts/deploy-apparmor-profiles.sh

# Validate setup
./scripts/validate-apparmor-profiles.sh
```

### Use Examples
```bash
# Start application stack
cd examples/
docker-compose up -d

# Test with custom nginx config
docker run --security-opt apparmor=docker-nginx-restrictive \
  -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf:ro \
  nginx:alpine
```

## Learning Objectives

By completing this lab, you will:

- ✅ Understand AppArmor's role in container security
- ✅ Create and apply custom security profiles
- ✅ Monitor and respond to security violations
- ✅ Integrate AppArmor with Docker workflows
- ✅ Troubleshoot profile and container issues
- ✅ Implement production-ready security configurations

## Prerequisites

- **Operating System**: Ubuntu 24.04 LTS
- **Software**: Docker Engine (latest stable)
- **Permissions**: sudo/root access
- **Knowledge**: Basic Docker concepts and Linux command line

## Support

For issues or questions:
1. Check the troubleshooting section in the main lab
2. Use the debug script for diagnostic information
3. Review AppArmor logs and Docker container status
4. Consult the official documentation links provided

## Next Steps

After completing this lab:
- Explore integration with seccomp profiles
- Investigate SELinux alternatives where applicable
- Study Kubernetes Pod Security Standards
- Review container runtime security tools

Happy learning! 🐳🔒
