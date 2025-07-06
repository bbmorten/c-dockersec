#!/bin/bash
IMAGE=$1

echo "=== Security Scan for $IMAGE ==="

# Basic security checks
echo -e "\n[Configuration Checks]"
docker inspect $IMAGE --format '
Base Image: {{.Config.Image}}
User: {{.Config.User}}
Exposed Ports: {{.Config.ExposedPorts}}
Entrypoint: {{.Config.Entrypoint}}
Cmd: {{.Config.Cmd}}'

# Check for vulnerabilities
echo -e "\n[Vulnerability Scan]"
if command -v trivy &> /dev/null; then
    trivy image --severity HIGH,CRITICAL $IMAGE
else
    echo "Trivy not installed - skipping vulnerability scan"
fi

# Check image size
echo -e "\n[Image Size]"
docker images $IMAGE --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# Check for sensitive files
echo -e "\n[Checking for Sensitive Files]"
docker run --rm --entrypoint sh $IMAGE -c '
    for file in /etc/passwd /etc/shadow /.ssh /root/.ssh; do
        if [ -e "$file" ]; then
            echo "Found: $file"
        fi
    done
'

# Check installed packages
echo -e "\n[Installed Packages]"
docker run --rm --entrypoint sh $IMAGE -c '
    if command -v apk &> /dev/null; then
        echo "Alpine packages:"
        apk list --installed | wc -l
    elif command -v dpkg &> /dev/null; then
        echo "Debian packages:"
        dpkg -l | wc -l
    fi
'
SCRIPT

chmod +x ../scan-hardened-image.sh

# Run security scan
echo -e "\nScanning hardened image..."
cd ..
./scan-hardened-image.sh $IMAGE_NAME:$VERSION

echo "Hardened base image created: $IMAGE_NAME:$VERSION"
EOF

chmod +x create-hardened-base.sh
./create-hardened-base.sh

# Create comprehensive hardening script for any application
cat > harden-application.sh << 'EOF'
#!/bin/bash

# Application Hardening Framework
# Implements all Docker security best practices

APP_NAME=$1
DOCKERFILE=$2

if [ -z "$APP_NAME" ] || [ -z "$DOCKERFILE" ]; then
    echo "Usage: $0 <app_name> <dockerfile_path>"
    exit 1
fi

echo "=== Hardening Application: $APP_NAME ==="

# Create hardened version
HARDENED_DIR="${APP_NAME}-hardened"
mkdir -p $HARDENED_DIR

# Analyze original Dockerfile
echo "Analyzing original Dockerfile..."
cp $DOCKERFILE $HARDENED_DIR/Dockerfile.original

# Create hardened Dockerfile
cat > $HARDENED_DIR/Dockerfile << 'DOCKERFILE'
# HARDENED DOCKERFILE - Auto-generated
# Based on Docker security best practices

# Multi-stage build for smaller attack surface
FROM alpine:3.18 AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    git

# Copy source code
WORKDIR /build
COPY . .

# Build application (customize as needed)
# RUN make build

# Final stage - minimal runtime
FROM alpine:3.18

# Install runtime dependencies only
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
        ca-certificates \
        tzdata && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S -G appgroup -h /app appuser

# Copy application from builder
COPY --from=builder --chown=appuser:appgroup /build/app /app/

# Set up runtime directory
WORKDIR /app

# Drop all capabilities
RUN setcap -r /app/* 2>/dev/null || true

# Switch to non-root user
USER appuser

# Security labels
LABEL security.hardened="true" \
      security.scan_date="$(date -u +%Y-%m-%d)" \
      maintainer="security-team"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "echo 'Health check' || exit 1"]

# Run application
ENTRYPOINT ["/app/entrypoint.sh"]
DOCKERFILE

# Create security-enhanced docker-compose
cat > $HARDENED_DIR/docker-compose.yml << 'COMPOSE'
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    image: ${APP_NAME}:hardened
    container_name: ${APP_NAME}-secure
    restart: unless-stopped
    
    # Security configuration
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
      # - seccomp:seccomp-profile.json
    
    # Capabilities
    cap_drop:
      - ALL
    cap_add:
      # Add only required capabilities
      # - NET_BIND_SERVICE
    
    # Read-only root filesystem
    read_only: true
    
    # Temporary filesystems for writable areas
    tmpfs:
      - /tmp:noexec,nosuid,nodev,size=100M
      - /run:noexec,nosuid,nodev,size=10M
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
          pids: 100
        reservations:
          cpus: '0.1'
          memory: 128M
    
    # Networking
    networks:
      - internal
    
    # Logging
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    
    # Environment variables (use secrets in production)
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=info

networks:
  internal:
    driver: bridge
    internal: true
    
# Secrets (for sensitive data)
# secrets:
#   app_secret:
#     file: ./secrets/app_secret.txt
COMPOSE

# Create AppArmor profile
cat > $HARDENED_DIR/apparmor-profile << 'APPARMOR'
#include <tunables/global>

profile ${APP_NAME}-container flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  
  # Network
  network inet tcp,
  network inet udp,
  deny network raw,
  
  # Filesystem
  / r,
  /app/** r,
  /tmp/** rw,
  /run/** rw,
  
  # Deny sensitive paths
  deny /etc/shadow r,
  deny /etc/sudoers r,
  deny /**/.ssh/** rw,
  deny /root/** rw,
  deny /home/** rw,
  deny /var/log/** w,
  
  # Capabilities
  deny capability dac_override,
  deny capability setuid,
  deny capability setgid,
  deny capability net_admin,
  deny capability sys_admin,
  
  # No ptrace
  deny ptrace,
  
  # No mount
  deny mount,
}
APPARMOR

# Create seccomp profile
cat > $HARDENED_DIR/seccomp-profile.json << 'SECCOMP'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86"],
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "access", "arch_prctl", "bind", "brk",
        "capset", "chdir", "chmod", "chown", "clock_getres", "clock_gettime",
        "clone", "close", "connect", "dup", "dup2", "epoll_create",
        "epoll_create1", "epoll_ctl", "epoll_wait", "execve", "exit",
        "exit_group", "fchmod", "fchown", "fcntl", "fstat", "futex",
        "getcwd", "getdents", "getdents64", "getegid", "geteuid",
        "getgid", "getgroups", "getpeername", "getpgrp", "getpid",
        "getppid", "getrlimit", "getsockname", "getsockopt", "gettid",
        "getuid", "ioctl", "kill", "listen", "lseek", "lstat", "madvise",
        "mkdir", "mmap", "mprotect", "munmap", "nanosleep", "open",
        "openat", "pipe", "poll", "prctl", "pread64", "pwrite64",
        "read", "readlink", "recvfrom", "recvmsg", "rename", "rmdir",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sched_getaffinity",
        "sched_yield", "select", "sendmsg", "sendto", "set_tid_address",
        "setgid", "setgroups", "setsockopt", "setuid", "shutdown",
        "sigaltstack", "socket", "stat", "statfs", "tgkill", "time",
        "uname", "unlink", "wait4", "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
SECCOMP

# Create security scanning script
cat > $HARDENED_DIR/security-check.sh << 'CHECK'
#!/bin/bash

echo "=== Security Check for ${APP_NAME} ==="

# Build hardened image
docker-compose build

# Run security scans
echo -e "\n[Vulnerability Scan]"
trivy image ${APP_NAME}:hardened

echo -e "\n[Docker Bench Security]"
docker run --rm --net host --pid host --cap-add audit_control \
    -v /var/lib:/var/lib \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /etc:/etc \
    docker/docker-bench-security

echo -e "\n[Configuration Audit]"
docker inspect ${APP_NAME}:hardened | jq '.[0].Config'

echo -e "\n[Size Comparison]"
echo "Original: $(docker images ${APP_NAME}:latest --format '{{.Size}}' 2>/dev/null || echo 'N/A')"
echo "Hardened: $(docker images ${APP_NAME}:hardened --format '{{.Size}}')"
CHECK

chmod +x $HARDENED_DIR/security-check.sh

echo "
Hardening complete! Files created in $HARDENED_DIR/:
- Dockerfile (hardened version)
- docker-compose.yml (with security settings)
- apparmor-profile (application profile)
- seccomp-profile.json (syscall filtering)
- security-check.sh (validation script)

Next steps:
1. Review and customize the Dockerfile for your application
2. Test the hardened image
3. Run security-check.sh to validate
4. Deploy with docker-compose up
"
EOF

chmod +x harden-application.sh
```

**Exercise 2: Implement Runtime Protection**

```bash
# Create runtime protection framework
cat > runtime-protection.sh << 'EOF'
#!/bin/bash

# Docker Runtime Protection Framework
# Implements continuous security monitoring and enforcement

ACTION=$1

case "$ACTION" in
    setup)
        echo "=== Setting up Runtime Protection ==="
        
        # Create monitoring directory
        mkdir -p /var/lib/docker-security/{logs,alerts,policies}
        
        # Install dependencies
        echo "Installing dependencies..."
        sudo apt-get update
        sudo apt-get install -y \
            auditd \
            sysdig \
            jq \
            python3-pip
        
        pip3 install docker pyyaml
        
        # Configure Docker daemon for security
        echo "Configuring Docker daemon..."
        sudo tee /etc/docker/daemon.json << 'DAEMON'
{
    "log-level": "info",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3",
        "labels": "security"
    },
    "storage-driver": "overlay2",
    "storage-opts": [
        "overlay2.override_kernel_check=true"
    ],
    "default-runtime": "runc",
    "runtimes": {
        "runc": {
            "path": "runc"
        }
    },
    "exec-opts": ["native.cgroupdriver=systemd"],
    "features": {
        "buildkit": true
    },
    "experimental": false,
    "metrics-addr": "127.0.0.1:9323"
}
DAEMON
        
        # Configure audit rules for Docker
        echo "Setting up audit rules..."
        sudo tee -a /etc/audit/rules.d/docker.rules << 'AUDIT'
# Docker audit rules
-w /usr/bin/docker -p rwxa -k docker
-w /var/lib/docker -p rwxa -k docker
-w /etc/docker -p rwxa -k docker
-w /var/run/docker.sock -p rwxa -k docker
-w /usr/bin/containerd -p rwxa -k docker
-w /usr/bin/runc -p rwxa -k docker
AUDIT
        
        sudo systemctl restart auditd
        sudo systemctl restart docker
        
        echo "Runtime protection setup complete!"
        ;;
        
    monitor)
        echo "=== Starting Runtime Monitoring ==="
        
        # Create monitoring daemon
        cat > /tmp/docker-monitor.py << 'MONITOR'
#!/usr/bin/env python3
import docker
import json
import time
import logging
import yaml
from datetime import datetime
from threading import Thread

class DockerRuntimeMonitor:
    def __init__(self):
        self.client = docker.from_env()
        self.policies = self.load_policies()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/lib/docker-security/logs/monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_policies(self):
        """Load security policies"""
        default_policies = {
            'forbidden_images': ['mining', 'hack', 'exploit'],
            'required_labels': ['security.scan'],
            'max_containers': 50,
            'resource_limits': {
                'memory': '2G',
                'cpu': '2.0'
            }
        }
        try:
            with open('/var/lib/docker-security/policies/runtime.yaml', 'r') as f:
                return yaml.safe_load(f)
        except:
            return default_policies
            
    def check_container(self, container):
        """Check container against security policies"""
        violations = []
        
        # Check image name
        image_name = container.image.tags[0] if container.image.tags else 'unknown'
        for forbidden in self.policies.get('forbidden_images', []):
            if forbidden in image_name.lower():
                violations.append(f"Forbidden image pattern: {forbidden}")
                
        # Check configuration
        attrs = container.attrs
        if attrs['HostConfig']['Privileged']:
            violations.append("Container running in privileged mode")
            
        if attrs['Config']['User'] in ['', 'root', '0']:
            violations.append("Container running as root")
            
        # Check capabilities
        dangerous_caps = ['SYS_ADMIN', 'SYS_MODULE', 'SYS_RAWIO']
        cap_add = attrs['HostConfig'].get('CapAdd', [])
        for cap in cap_add:
            if cap in dangerous_caps:
                violations.append(f"Dangerous capability: {cap}")
                
        return violations
        
    def enforce_policies(self, container, violations):
        """Enforce security policies"""
        if violations:
            self.logger.warning(f"Container {container.name} has violations: {violations}")
            
            # Write alert
            alert = {
                'timestamp': datetime.now().isoformat(),
                'container': container.name,
                'violations': violations,
                'action': 'blocked'
            }
            
            with open('/var/lib/docker-security/alerts/latest.json', 'w') as f:
                json.dump(alert, f)
                
            # Take action based on severity
            if any('privileged' in v.lower() for v in violations):
                self.logger.critical(f"Stopping privileged container: {container.name}")
                container.stop()
                container.remove()
                
    def monitor_events(self):
        """Monitor Docker events"""
        for event in self.client.events(decode=True):
            if event['Type'] == 'container' and event['Action'] == 'start':
                container_id = event['id']
                try:
                    container = self.client.containers.get(container_id)
                    violations = self.check_container(container)
                    self.enforce_policies(container, violations)
                except Exception as e:
                    self.logger.error(f"Error checking container: {e}")
                    
    def periodic_scan(self):
        """Periodic security scan of all containers"""
        while True:
            try:
                containers = self.client.containers.list()
                self.logger.info(f"Scanning {len(containers)} containers...")
                
                for container in containers:
                    violations = self.check_container(container)
                    if violations:
                        self.logger.warning(f"Container {container.name}: {violations}")
                        
            except Exception as e:
                self.logger.error(f"Scan error: {e}")
                
            time.sleep(300)  # Scan every 5 minutes
            
    def run(self):
        """Start monitoring"""
        self.logger.info("Docker Runtime Monitor started")
        
        # Start event monitoring
        event_thread = Thread(target=self.monitor_events)
        event_thread.daemon = True
        event_thread.start()
        
        # Start periodic scanning
        scan_thread = Thread(target=self.periodic_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Monitor stopped")

if __name__ == "__main__":
    monitor = DockerRuntimeMonitor()
    monitor.run()
MONITOR
        
        # Run monitor
        python3 /tmp/docker-monitor.py
        ;;
        
    audit)
        echo "=== Docker Security Audit ==="
        
        # Check Docker daemon configuration
        echo -e "\n[Docker Daemon Security]"
        docker info --format json | jq '.SecurityOptions'
        
        # Audit running containers
        echo -e "\n[Container Audit]"
        docker ps -q | while read container; do
            echo -e "\nContainer: $(docker inspect -f '{{.Name}}' $container)"
            docker inspect $container --format '
Security Profile:
  Privileged: {{.HostConfig.Privileged}}
  User: {{.Config.User}}
  AppArmor: {{index .HostConfig.SecurityOpt}}
  Capabilities: {{.HostConfig.CapAdd}}
  ReadOnly FS: {{.HostConfig.ReadonlyRootfs}}'
        done
        
        # Check for security events
        echo -e "\n[Recent Security Events]"
        sudo ausearch -k docker -ts recent | tail -20
        
        # Resource usage
        echo -e "\n[Resource Usage]"
        docker stats --no-stream
        ;;
        
    harden)
        CONTAINER=$2
        if [ -z "$CONTAINER" ]; then
            echo "Usage: $0 harden <container_name>"
            exit 1
        fi
        
        echo "=== Hardening Container: $CONTAINER ==="
        
        # Get current configuration
        CONFIG=$(docker inspect $CONTAINER)
        IMAGE=$(echo $CONFIG | jq -r '.[0].Config.Image')
        
        # Stop container
        docker stop $CONTAINER
        
        # Restart with hardened configuration
        docker run -d \
            --name ${CONTAINER}-hardened \
            --user 1000:1000 \
            --cap-drop ALL \
            --cap-add NET_BIND_SERVICE \
            --read-only \
            --tmpfs /tmp:noexec,nosuid,size=100M \
            --security-opt no-new-privileges:true \
            --security-opt apparmor=docker-default \
            --memory 512m \
            --cpus 1 \
            --pids-limit 100 \
            --restart unless-stopped \
            $IMAGE
            
        echo "Hardened container started: ${CONTAINER}-hardened"
        ;;
        
    *)
        echo "Docker Runtime Protection"
        echo "Usage: $0 {setup|monitor|audit|harden}"
        echo ""
        echo "Commands:"
        echo "  setup   - Set up runtime protection"
        echo "  monitor - Start runtime monitoring"
        echo "  audit   - Audit security configuration"
        echo "  harden  - Harden a running container"
        ;;
esac
EOF

chmod +x runtime-protection.sh

# Test runtime protection
echo "=== Testing Runtime Protection ==="

# Create test containers
echo -e "\n[Creating test scenarios]"

# Scenario 1: Privileged container (should be blocked)
echo "Test 1: Attempting to run privileged container..."
docker run -d --name test-privileged --privileged alpine sleep 300 2>/dev/null && \
    echo "✗ RISK: Privileged container allowed" || \
    echo "✓ PROTECTED: Privileged container blocked"

# Scenario 2: Container with dangerous capabilities
echo -e "\nTest 2: Container with SYS_ADMIN capability..."
docker run -d --name test-sysadmin --cap-add SYS_ADMIN alpine sleep 300

# Scenario 3: Properly hardened container
echo -e "\nTest 3: Running hardened container..."
docker run -d --name test-hardened \
    --user 1000:1000 \
    --cap-drop ALL \
    --read-only \
    --security-opt no-new-privileges:true \
    alpine sleep 300

# Run audit
./runtime-protection.sh audit

# Cleanup
docker stop test-privileged test-sysadmin test-hardened 2>/dev/null
docker rm test-privileged test-sysadmin test-hardened 2>/dev/null
```

## Section 3.6: Module Assessment (30 minutes)

### Final Project: Comprehensive Container Security Implementation

Create a complete secure containerized application with all security controls:

```bash
# Create final project directory
mkdir -p ~/docker-security-labs/module3/final-project
cd ~/docker-security-labs/module3/final-project

# Project scaffold
cat > project-requirements.md << 'EOF'
# Container Security Final Project

## Objective
Deploy a multi-container application with comprehensive security controls

## Requirements

### 1. Security Architecture
- [ ] Implement defense in depth
- [ ] Use least privilege principle
- [ ] Enable all available security features

### 2. Container Hardening
- [ ] Non-root users
- [ ] Minimal base images
- [ ] Read-only filesystems
- [ ] Dropped capabilities
- [ ] Resource limits

### 3. Security Profiles
- [ ] Custom AppArmor profiles
- [ ] Restrictive seccomp filters
- [ ] User namespace remapping

### 4. Runtime Protection
- [ ] Continuous monitoring
- [ ] Anomaly detection
- [ ] Automated response

### 5. Incident Response
- [ ] Detection procedures
- [ ] Forensic collection
- [ ] Recovery plans

## Deliverables
1. Hardened application containers
2. Security documentation
3. Monitoring dashboard
4. Incident response playbook
5. Security audit report
EOF

# Create sample application
cat > app.py << 'EOF'
from flask import Flask, jsonify
import os
import socket

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({
        'service': 'secure-api',
        'version': '1.0.0',
        'host': socket.gethostname(),
        'user': os.getenv('USER', 'unknown')
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

# Create complete secure deployment
cat > docker-compose.secure.yml << 'EOF'
version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile.secure
    image: secure-api:latest
    container_name: secure-api
    
    # User configuration
    user: "10001:10001"
    
    # Security options
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-custom
      - seccomp:seccomp-strict.json
    
    # Capabilities
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    
    # Filesystem
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,nodev,size=50M
      - /run:noexec,nosuid,nodev,size=10M
    
    # Resources
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
          pids: 50
        reservations:
          cpus: '0.1'
          memory: 128M
    
    # Health check
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:5000/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 10s
    
    # Network
    networks:
      - internal
    expose:
      - "5000"
    
    # Logging
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service,security"
    
    # Labels
    labels:
      security.hardened: "true"
      security.scan: "passed"
      maintainer: "security-team"
  
  # Security monitoring sidecar
  monitor:
    image: falcosecurity/falco:latest
    container_name: security-monitor
    privileged: true
    
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock:ro
      - /dev:/host/dev:ro
      - /proc:/host/proc:ro
      - ./falco-rules.yaml:/etc/falco/rules.d/custom.yaml:ro
    
    networks:
      - monitoring
    
    command: ["/usr/bin/falco", "-pk"]

  # Reverse proxy with security headers
  proxy:
    image: nginx:alpine
    container_name: secure-proxy
    
    # Security configuration
    user: "101:101"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    
    read_only: true
    tmpfs:
      - /var/cache/nginx:noexec,nosuid,nodev
      - /var/run:noexec,nosuid,nodev
    
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    
    networks:
      - internal
      - external
    
    ports:
      - "443:443"
    
    depends_on:
      - api

networks:
  internal:
    driver: bridge
    internal: true
  external:
    driver: bridge
  monitoring:
    driver: bridge
EOF

# Create Dockerfile with all security features
cat > Dockerfile.secure << 'EOF'
# Multi-stage build for security
FROM python:3.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Create app user early
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S -G appgroup -h /app appuser

# Install Python dependencies
WORKDIR /build
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-alpine

# Security updates
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
        ca-certificates \
        tzdata && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S -G appgroup -h /app appuser

# Copy Python packages from builder
COPY --from=builder --chown=appuser:appgroup /root/.local /home/appuser/.local

# Copy application
WORKDIR /app
COPY --chown=appuser:appgroup app.py .

# Set Python path
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONPATH=/home/appuser/.local/lib/python3.11/site-packages

# Remove unnecessary binaries
RUN rm -rf /usr/bin/wget \
           /usr/bin/curl \
           /sbin/apk

# Switch to non-root user
USER appuser

# Security labels
LABEL security.hardened="true" \
      security.nonroot="true" \
      security.updates="2024-01-01"

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Run application
EXPOSE 5000
ENTRYPOINT ["python"]
CMD ["app.py"]
EOF

# Create requirements.txt
cat > requirements.txt << 'EOF'
flask==2.3.3
gunicorn==21.2.0
EOF

# Create comprehensive security audit script
cat > security-audit.sh << 'EOF'
#!/bin/bash

echo "=== Comprehensive Security Audit ==="
echo "Date: $(date)"
echo ""

# Function to check security
check_security() {
    local container=$1
    local score=0
    local max_score=10
    
    echo "Auditing container: $container"
    
    # Check if running as non-root
    user=$(docker inspect -f '{{.Config.User}}' $container)
    if [ ! -z "$user" ] && [ "$user" != "root" ]; then
        echo "✓ Running as non-root user: $user"
        ((score++))
    else
        echo "✗ Running as root"
    fi
    
    # Check privileged mode
    privileged=$(docker inspect -f '{{.HostConfig.Privileged}}' $container)
    if [ "$privileged" == "false" ]; then
        echo "✓ Not running in privileged mode"
        ((score++))
    else
        echo "✗ Running in privileged mode"
    fi
    
    # Check capabilities
    caps=$(docker inspect -f '{{.HostConfig.CapDrop}}' $container)
    if [[ "$caps" == *"ALL"* ]]; then
        echo "✓ All capabilities dropped"
        ((score++))
    else
        echo "**Exercise 1: Configure User Namespace Remapping**

```bash
cd ~/docker-security-labs/module3/lab3

# Check current Docker user namespace configuration
docker info | grep -i "user"

# Set up user namespace remapping
# First, create subordinate UID/GID mappings
echo "=== Setting up User Namespace Remapping ==="

# Check if dockremap user exists, if not create it
if ! id dockremap &>/dev/null; then
    sudo useradd -r -s /bin/false dockremap
fi

# Configure subordinate UIDs and GIDs
echo "dockremap:231072:65536" | sudo tee -a /etc/subuid
echo "dockremap:231072:65536" | sudo tee -a /etc/subgid

# Create Docker daemon configuration
sudo tee /etc/docker/daemon.json << 'EOF'
{
    "userns-remap": "default",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2"
}
EOF

# Restart Docker to apply changes
echo "Restarting Docker daemon..."
sudo systemctl restart docker

# Verify user namespace is enabled
docker info | grep -A2 "Security Options"

# Test user namespace mapping
cat > test-userns.sh << 'EOF'
#!/bin/sh
echo "=== User Namespace Test ==="
echo "Inside container:"
echo "User: $(id)"
echo "Process info:"
ps aux | head -5

# Try privileged operations
echo -e "\nTesting privileged operations:"

# Test 1: Create setuid binary
cp /bin/sh /tmp/setuid-test 2>/dev/null
chmod 4755 /tmp/setuid-test 2>/dev/null
if [ -u /tmp/setuid-test ]; then
    echo "✗ RISK: Can create setuid binaries"
else
    echo "✓ PROTECTED: Cannot create setuid binaries"
fi

# Test 2: Modify system files
if echo "test" > /etc/test 2>/dev/null; then
    echo "✗ RISK: Can modify /etc"
    rm /etc/test
else
    echo "✓ PROTECTED: Cannot modify /etc"
fi

# Test 3: Load kernel module
if modprobe dummy 2>/dev/null; then
    echo "✗ RISK: Can load kernel modules"
else
    echo "✓ PROTECTED: Cannot load kernel modules"
fi
EOF

chmod +x test-userns.sh

# Run container with user namespaces enabled
echo -e "\n=== Running container WITH user namespace remapping ==="
docker run --rm -v $(pwd)/test-userns.sh:/test.sh:ro alpine /test.sh

# Check the actual UID on the host
echo -e "\n=== Host view of container processes ==="
docker run -d --name userns-demo alpine sleep 300
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' userns-demo)
echo "Container PID: $CONTAINER_PID"
echo "Process running as:"
ps -p $CONTAINER_PID -o pid,uid,gid,comm

# Show UID mapping
echo -e "\n=== UID/GID Mapping ==="
if [ -f /proc/$CONTAINER_PID/uid_map ]; then
    echo "UID map:"
    cat /proc/$CONTAINER_PID/uid_map
    echo "GID map:"
    cat /proc/$CONTAINER_PID/gid_map
fi

docker stop userns-demo
```

**Exercise 2: Rootless Docker Installation and Configuration**

```bash
# Install rootless Docker (alternative to daemon remapping)
cat > install-rootless.sh << 'EOF'
#!/bin/bash
echo "=== Installing Rootless Docker ==="

# Check prerequisites
if ! command -v newuidmap &> /dev/null; then
    echo "Installing uidmap package..."
    sudo apt-get update && sudo apt-get install -y uidmap
fi

# Check kernel support
if ! grep -q "^kernel.unprivileged_userns_clone = 1" /etc/sysctl.conf; then
    echo "Enabling unprivileged user namespaces..."
    echo "kernel.unprivileged_userns_clone = 1" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
fi

# Download and run rootless installation script
curl -fsSL https://get.docker.com/rootless | sh

# Set up environment
echo "Setting up environment..."
cat >> ~/.bashrc << 'BASHRC'
export PATH=$HOME/bin:$PATH
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock
BASHRC

# Create systemd user service
systemctl --user start docker
systemctl --user enable docker

echo "Rootless Docker installed!"
echo "Please log out and back in for changes to take effect"
EOF

chmod +x install-rootless.sh

# For demonstration, we'll simulate rootless behavior
echo -e "\n=== Demonstrating Rootless Docker Security ==="

# Create a comparison script
cat > compare-root-rootless.sh << 'EOF'
#!/bin/bash

echo "=== Comparing Root vs Rootless Docker Security ==="

# Function to test Docker security
test_docker_security() {
    local mode=$1
    echo -e "\n[$mode Docker]"
    
    # Test 1: Check effective user
    echo -n "Docker daemon runs as: "
    if [ "$mode" == "Root" ]; then
        ps aux | grep dockerd | grep -v grep | awk '{print $1}'
    else
        echo "$USER (simulated)"
    fi
    
    # Test 2: Check socket permissions
    echo -n "Docker socket owner: "
    if [ "$mode" == "Root" ]; then
        ls -l /var/run/docker.sock | awk '{print $3":"$4}'
    else
        echo "$USER:$USER (simulated)"
    fi
    
    # Test 3: Container root mapping
    echo -n "Container root maps to: "
    if [ "$mode" == "Root" ]; then
        echo "Host root (uid 0)"
    else
        echo "Unprivileged user (uid $UID)"
    fi
}

test_docker_security "Root"
test_docker_security "Rootless"

echo -e "\n=== Security Implications ==="
echo "Root Docker:"
echo "  - Container escape → root on host"
echo "  - Requires trusted users only"
echo "  - Full system access possible"

echo -e "\nRootless Docker:"
echo "  - Container escape → unprivileged user"
echo "  - Safe for untrusted workloads"
echo "  - Limited to user's permissions"
EOF

chmod +x compare-root-rootless.sh
./compare-root-rootless.sh
```

### Section 3.4: Runtime Security Monitoring and Incident Response (75 minutes)

Docker daemon security is critical as it requires root privileges unless you opt-in to Rootless mode. We need comprehensive monitoring to detect and respond to security incidents.

### Lab 3.4: Runtime Security Implementation

**Exercise 1: Deploy Falco for Runtime Security**

```bash
cd ~/docker-security-labs/module3/lab4

# Install Falco
cat > install-falco.sh << 'EOF'
#!/bin/bash
echo "=== Installing Falco Runtime Security ==="

# Add Falco repository
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | sudo apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | \
    sudo tee /etc/apt/sources.list.d/falcosecurity.list

# Update and install
sudo apt-get update -y
sudo apt-get install -y linux-headers-$(uname -r)
sudo apt-get install -y falco

# Start Falco service
sudo systemctl start falco
sudo systemctl enable falco

echo "Falco installed and running!"
EOF

chmod +x install-falco.sh
# Note: In production, run this script. For demo, we'll simulate Falco behavior

# Create custom Falco rules for Docker security
sudo tee /etc/falco/rules.d/docker-security.yaml << 'EOF'
#
# Docker Security Rules for Falco
#

- rule: Docker Daemon API Access
  desc: Detect access to Docker daemon socket
  condition: >
    (evt.type=open or evt.type=connect) and 
    (fd.name=/var/run/docker.sock or 
     fd.name contains "/docker.sock")
  output: >
    Docker socket accessed (user=%user.name command=%proc.cmdline 
    file=%fd.name container=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [docker, daemon, mitre_privilege_escalation]

- rule: Container Escape Attempt
  desc: Detect potential container escape attempts
  condition: >
    spawned_process and 
    container.id != host and
    (proc.name in (nsenter, setns) or
     (proc.name=docker and proc.cmdline contains "exec" and 
      proc.cmdline contains "--privileged"))
  output: >
    Container escape attempt detected (user=%user.name command=%proc.cmdline 
    container=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation]

- rule: Suspicious Container Activity
  desc: Detect suspicious activities within containers
  condition: >
    container.id != host and
    (
      (spawned_process and proc.name in (nc, ncat, netcat, socat, nmap)) or
      (evt.type=open and (fd.name contains /etc/shadow or 
                          fd.name contains /etc/sudoers or
                          fd.name contains /.ssh/)) or
      (spawned_process and proc.name in (curl, wget) and 
       proc.cmdline contains "http" and 
       not proc.pname in (apt-get, yum, apk))
    )
  output: >
    Suspicious container activity (user=%user.name command=%proc.cmdline 
    file=%fd.name container=%container.id image=%container.image.repository)
  priority: ERROR
  tags: [container, suspicious, mitre_discovery]

- rule: Privileged Container Started
  desc: Detect when a privileged container is started
  condition: >
    container_started and 
    container.privileged=true
  output: >
    Privileged container started (user=%user.name 
    container=%container.id image=%container.image.repository)
  priority: WARNING
  tags: [container, privileged, configuration]

- rule: Container Volume Mount Sensitive Path
  desc: Detect containers mounting sensitive host paths
  condition: >
    container_started and
    (container.mount.dest[/] = "/" or
     container.mount.dest[/etc] = "/etc" or
     container.mount.dest[/var/run/docker.sock] != "N/A")
  output: >
    Container mounting sensitive path (user=%user.name 
    mount=%container.mount.dest container=%container.id 
    image=%container.image.repository)
  priority: ERROR
  tags: [container, mount, configuration]

- rule: Cryptocurrency Mining Detected
  desc: Detect cryptocurrency mining activities
  condition: >
    spawned_process and
    (proc.name in (minerd, xmrig, minergate) or
     (proc.name in (python, python3, perl, ruby, node) and 
      (proc.cmdline contains "stratum+tcp" or 
       proc.cmdline contains "mining" or
       proc.cmdline contains "monero")))
  output: >
    Cryptocurrency mining detected (user=%user.name command=%proc.cmdline 
    container=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [cryptomining, malware, mitre_impact]
EOF

# Create runtime monitoring script
cat > runtime-monitor.py << 'EOF'
#!/usr/bin/env python3
import docker
import json
import time
from datetime import datetime
import threading
import signal
import sys

class DockerSecurityMonitor:
    def __init__(self):
        self.client = docker.from_env()
        self.running = True
        self.alerts = []
        
    def stop(self):
        self.running = False
        
    def check_container_security(self, container):
        """Check container for security issues"""
        issues = []
        
        try:
            # Get container details
            info = container.attrs
            config = info.get('Config', {})
            host_config = info.get('HostConfig', {})
            
            # Check 1: Privileged mode
            if host_config.get('Privileged', False):
                issues.append({
                    'severity': 'CRITICAL',
                    'issue': 'Container running in privileged mode',
                    'recommendation': 'Remove --privileged flag'
                })
            
            # Check 2: User running as root
            if not config.get('User') or config.get('User') == 'root':
                issues.append({
                    'severity': 'HIGH',
                    'issue': 'Container running as root user',
                    'recommendation': 'Use USER directive in Dockerfile'
                })
            
            # Check 3: Dangerous capabilities
            cap_add = host_config.get('CapAdd', [])
            dangerous_caps = ['SYS_ADMIN', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE']
            for cap in cap_add:
                if cap in dangerous_caps:
                    issues.append({
                        'severity': 'HIGH',
                        'issue': f'Dangerous capability added: {cap}',
                        'recommendation': f'Remove capability {cap}'
                    })
            
            # Check 4: Host network mode
            if host_config.get('NetworkMode') == 'host':
                issues.append({
                    'severity': 'HIGH',
                    'issue': 'Container using host network mode',
                    'recommendation': 'Use bridge network instead'
                })
            
            # Check 5: Docker socket mounted
            mounts = host_config.get('Mounts', [])
            for mount in mounts:
                if mount.get('Source') == '/var/run/docker.sock':
                    issues.append({
                        'severity': 'CRITICAL',
                        'issue': 'Docker socket mounted in container',
                        'recommendation': 'Remove Docker socket mount'
                    })
            
            # Check 6: No security options
            security_opt = host_config.get('SecurityOpt', [])
            if not security_opt:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'No security options configured',
                    'recommendation': 'Add security options (AppArmor, seccomp)'
                })
            
            # Check 7: No resource limits
            if not host_config.get('Memory') and not host_config.get('CpuQuota'):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'No resource limits configured',
                    'recommendation': 'Set memory and CPU limits'
                })
                
        except Exception as e:
            print(f"Error checking container {container.name}: {str(e)}")
            
        return issues
    
    def monitor_events(self):
        """Monitor Docker events"""
        for event in self.client.events(decode=True):
            if not self.running:
                break
                
            event_type = event.get('Type')
            action = event.get('Action')
            
            # Monitor container events
            if event_type == 'container':
                if action in ['start', 'create']:
                    container_id = event.get('id')
                    try:
                        container = self.client.containers.get(container_id)
                        issues = self.check_container_security(container)
                        
                        if issues:
                            alert = {
                                'timestamp': datetime.now().isoformat(),
                                'container': container.name,
                                'image': container.image.tags[0] if container.image.tags else 'unknown',
                                'issues': issues
                            }
                            self.alerts.append(alert)
                            self.print_alert(alert)
                    except:
                        pass
                        
    def print_alert(self, alert):
        """Print security alert"""
        print(f"\n{'='*60}")
        print(f"SECURITY ALERT - {alert['timestamp']}")
        print(f"Container: {alert['container']}")
        print(f"Image: {alert['image']}")
        print(f"Issues found: {len(alert['issues'])}")
        
        for issue in alert['issues']:
            print(f"\n[{issue['severity']}] {issue['issue']}")
            print(f"  → {issue['recommendation']}")
        
        print(f"{'='*60}\n")
        
    def check_running_containers(self):
        """Check all running containers"""
        print("Checking running containers...")
        containers = self.client.containers.list()
        
        for container in containers:
            issues = self.check_container_security(container)
            if issues:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'container': container.name,
                    'image': container.image.tags[0] if container.image.tags else 'unknown',
                    'issues': issues
                }
                self.alerts.append(alert)
                self.print_alert(alert)
        
        if not self.alerts:
            print("✓ No security issues found in running containers")
            
    def generate_report(self):
        """Generate security report"""
        if not self.alerts:
            print("\nNo security alerts to report")
            return
            
        print(f"\n{'='*60}")
        print("DOCKER SECURITY REPORT")
        print(f"Generated: {datetime.now().isoformat()}")
        print(f"Total alerts: {len(self.alerts)}")
        
        # Group by severity
        by_severity = {}
        for alert in self.alerts:
            for issue in alert['issues']:
                sev = issue['severity']
                by_severity[sev] = by_severity.get(sev, 0) + 1
        
        print("\nAlerts by severity:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in by_severity:
                print(f"  {sev}: {by_severity[sev]}")
        
        print(f"{'='*60}\n")

def signal_handler(sig, frame):
    print("\nShutting down monitor...")
    monitor.stop()
    sys.exit(0)

if __name__ == "__main__":
    monitor = DockerSecurityMonitor()
    signal.signal(signal.SIGINT, signal_handler)
    
    # Check existing containers
    monitor.check_running_containers()
    
    # Start monitoring
    print("\nMonitoring Docker events... (Press Ctrl+C to stop)")
    monitor_thread = threading.Thread(target=monitor.monitor_events)
    monitor_thread.start()
    
    # Keep main thread alive
    try:
        while monitor.running:
            time.sleep(1)
    except:
        monitor.stop()
    
    monitor_thread.join()
    monitor.generate_report()
EOF

chmod +x runtime-monitor.py

# Test the monitor with various containers
echo "=== Testing Runtime Security Monitor ==="

# Test 1: Insecure container
echo -e "\n[Test 1] Starting INSECURE container..."
docker run -d --name insecure-test \
    --privileged \
    --cap-add SYS_ADMIN \
    -v /var/run/docker.sock:/var/run/docker.sock \
    --network host \
    alpine sleep 300

# Test 2: Secure container
echo -e "\n[Test 2] Starting SECURE container..."
docker run -d --name secure-test \
    --user 1000:1000 \
    --cap-drop ALL \
    --read-only \
    --security-opt no-new-privileges:true \
    --memory 128m \
    --cpus 0.5 \
    alpine sleep 300

# Run the monitor
python3 runtime-monitor.py &
MONITOR_PID=$!

sleep 5

# Stop test containers
docker stop insecure-test secure-test
docker rm insecure-test secure-test

kill $MONITOR_PID 2>/dev/null
```

**Exercise 2: Incident Response Procedures**

```bash
# Create incident response toolkit
cat > docker-incident-response.sh << 'EOF'
#!/bin/bash

# Docker Incident Response Toolkit
# Based on Docker security best practices

INCIDENT_DIR="docker-incident-$(date +%Y%m%d-%H%M%S)"

case "$1" in
    detect)
        echo "=== Docker Security Detection ==="
        
        # Check for suspicious containers
        echo -e "\n[Checking for suspicious container names]"
        docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | \
            grep -iE "(miner|xmr|suspicious|hack|evil|malware)" || \
            echo "No suspicious container names detected"
        
        # Check for privileged containers
        echo -e "\n[Checking for privileged containers]"
        docker ps -q | xargs -I {} docker inspect {} \
            --format '{{if .HostConfig.Privileged}}{{.Name}}: PRIVILEGED{{end}}' | \
            grep -v '^# Module 3: Runtime Security and Container Hardening (Revised)

## Module Overview
Duration: 5 hours  
Format: Video lectures (2 hours), Hands-on labs (2.5 hours), Assessment (30 minutes)

## Learning Objectives
By the end of this module, you will be able to:
- Configure and implement Linux kernel security features for containers (capabilities, namespaces, cgroups)
- Deploy and manage security profiles using AppArmor, SELinux, and seccomp
- Implement user namespace remapping to prevent privilege escalation
- Monitor container runtime behavior and detect anomalies
- Respond effectively to container security incidents
- Apply defense-in-depth strategies to harden containers

---

## Section 3.1: Docker Security Architecture and Kernel Features (60 minutes)

### Video Lecture: Understanding Docker's Security Model

Based on Docker's official security documentation, there are four major areas to consider when reviewing Docker security: the intrinsic security of the kernel and its support for namespaces and cgroups, the attack surface of the Docker daemon itself, loopholes in the container configuration profile, and the "hardening" security features of the kernel.

#### The Four Pillars of Docker Security

1. **Kernel Security Features**
   - Namespaces for isolation
   - Control groups for resource management
   - Capabilities for privilege management

2. **Docker Daemon Security**
   - Attack surface considerations
   - Socket security
   - API endpoint protection

3. **Container Configuration**
   - Default vs. custom profiles
   - Security options and flags
   - Image security

4. **Kernel Hardening**
   - LSMs (AppArmor, SELinux)
   - Seccomp filtering
   - User namespaces

### Lab 3.1: Exploring Docker's Security Foundations

**Setup:**
```bash
mkdir -p ~/docker-security-labs/module3/lab1
cd ~/docker-security-labs/module3/lab1

# Verify kernel support for security features
cat > check-security.sh << 'EOF'
#!/bin/bash
echo "=== Docker Security Feature Check ==="

# Check kernel version
echo -e "\n[Kernel Version]"
uname -r

# Check namespace support
echo -e "\n[Namespace Support]"
ls -la /proc/self/ns/

# Check for user namespaces
echo -e "\n[User Namespace Support]"
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
    echo "User namespaces: $(cat /proc/sys/kernel/unprivileged_userns_clone)"
else
    echo "User namespaces: Checking alternative method..."
    grep CONFIG_USER_NS /boot/config-$(uname -r) || echo "Not found in kernel config"
fi

# Check security modules
echo -e "\n[Security Modules]"
if [ -f /sys/kernel/security/lsm ]; then
    echo "Active LSMs: $(cat /sys/kernel/security/lsm)"
fi

# Check AppArmor
if command -v aa-status &> /dev/null; then
    echo "AppArmor: Available"
    sudo aa-status --summary 2>/dev/null || echo "AppArmor: Permission needed for status"
else
    echo "AppArmor: Not installed"
fi

# Check SELinux
if command -v getenforce &> /dev/null; then
    echo "SELinux: $(getenforce)"
else
    echo "SELinux: Not installed"
fi

# Check Docker info
echo -e "\n[Docker Security Info]"
docker info --format '{{json .SecurityOptions}}' | jq . 2>/dev/null || docker info | grep -A5 "Security Options"

# Check default capabilities
echo -e "\n[Default Docker Capabilities]"
docker run --rm alpine sh -c 'apk add -q libcap 2>/dev/null && capsh --print | grep Current' || echo "Unable to check capabilities"
EOF

chmod +x check-security.sh
./check-security.sh
```

**Exercise 1: Understanding Capabilities**

By default, Docker starts containers with a restricted set of capabilities. Docker drops all capabilities except those needed, using an allowlist instead of a denylist approach.

```bash
# Create capability test script
cat > test-capabilities.sh << 'EOF'
#!/bin/sh
echo "=== Testing Docker Capability Restrictions ==="

# Function to test capability
test_cap() {
    local cap=$1
    local test_cmd=$2
    local desc=$3
    
    echo -e "\n[$cap] $desc"
    if eval $test_cmd 2>/dev/null; then
        echo "✓ SUCCESS: Capability available"
    else
        echo "✗ BLOCKED: Capability dropped (Good for security!)"
    fi
}

# Test various capabilities
test_cap "CAP_NET_BIND_SERVICE" "nc -l -p 80 &" "Bind to privileged port"
test_cap "CAP_SYS_ADMIN" "mount -t tmpfs tmpfs /mnt" "Mount filesystems"
test_cap "CAP_SYS_MODULE" "modprobe dummy" "Load kernel modules"
test_cap "CAP_SYS_TIME" "date -s '2030-01-01'" "Change system time"
test_cap "CAP_NET_RAW" "ping -c 1 google.com" "Use raw sockets"
test_cap "CAP_MKNOD" "mknod /tmp/test c 1 3" "Create device nodes"
test_cap "CAP_AUDIT_WRITE" "logger test" "Write audit logs"
test_cap "CAP_SETFCAP" "setcap cap_net_raw+p /bin/ping" "Set file capabilities"

# Show current capabilities
echo -e "\n[Current Capabilities]"
cat /proc/1/status | grep ^Cap
EOF

# Test with default capabilities
echo "=== Testing with DEFAULT Docker capabilities ==="
docker run --rm -v $(pwd)/test-capabilities.sh:/test.sh:ro alpine sh /test.sh

# Test with additional capabilities
echo -e "\n=== Testing with ADDED capabilities (less secure) ==="
docker run --rm --cap-add SYS_ADMIN --cap-add SYS_TIME \
    -v $(pwd)/test-capabilities.sh:/test.sh:ro alpine sh /test.sh

# Test with all capabilities dropped
echo -e "\n=== Testing with ALL capabilities dropped (most secure) ==="
docker run --rm --cap-drop ALL \
    -v $(pwd)/test-capabilities.sh:/test.sh:ro alpine sh /test.sh
```

**Exercise 2: Namespace Isolation**

When you start a container with docker run, behind the scenes Docker creates a set of namespaces and control groups for the container. Namespaces provide the first and most straightforward form of isolation.

```bash
# Create namespace exploration script
cat > explore-namespaces.sh << 'EOF'
#!/bin/bash

echo "=== Exploring Docker Namespace Isolation ==="

# Function to show namespace info
show_ns_info() {
    local container=$1
    local pid=$(docker inspect -f '{{.State.Pid}}' $container 2>/dev/null)
    
    if [ -z "$pid" ] || [ "$pid" = "0" ]; then
        echo "Container not running or PID not found"
        return
    fi
    
    echo -e "\nContainer: $container (PID: $pid)"
    echo "Namespaces:"
    sudo ls -la /proc/$pid/ns/ 2>/dev/null || echo "Need sudo to view namespaces"
}

# Start test containers
docker run -d --name ns-test1 --rm alpine sleep 300
docker run -d --name ns-test2 --rm alpine sleep 300

# Show host namespaces
echo "Host Namespaces:"
ls -la /proc/self/ns/

# Show container namespaces
show_ns_info ns-test1
show_ns_info ns-test2

# Compare namespace IDs
echo -e "\n=== Namespace Isolation Verification ==="
NS1_PID=$(docker inspect -f '{{.State.Pid}}' ns-test1)
NS2_PID=$(docker inspect -f '{{.State.Pid}}' ns-test2)

if [ ! -z "$NS1_PID" ] && [ ! -z "$NS2_PID" ]; then
    echo "Comparing PID namespaces:"
    echo "Container 1: $(sudo readlink /proc/$NS1_PID/ns/pid 2>/dev/null || echo 'Need sudo')"
    echo "Container 2: $(sudo readlink /proc/$NS2_PID/ns/pid 2>/dev/null || echo 'Need sudo')"
    echo "Host:        $(readlink /proc/self/ns/pid)"
fi

# Test process isolation
echo -e "\n=== Process Isolation Test ==="
echo "Processes visible in container 1:"
docker exec ns-test1 ps aux

echo -e "\nProcesses visible on host:"
ps aux | wc -l

# Cleanup
docker stop ns-test1 ns-test2 2>/dev/null
EOF

chmod +x explore-namespaces.sh
./explore-namespaces.sh
```

**Exercise 3: Control Groups (cgroups)**

Control Groups are another key component of Linux containers. They implement resource accounting and limiting... they are essential to fend off some denial-of-service attacks.

```bash
# Create cgroup testing script
cat > test-cgroups.sh << 'EOF'
#!/bin/bash

echo "=== Testing Docker Control Groups (cgroups) ==="

# Memory limit test
echo -e "\n[Memory Limit Test]"
echo "Starting container with 128MB memory limit..."
docker run -d --name mem-test --memory="128m" --rm alpine sh -c '
    echo "Allocating memory...";
    dd if=/dev/zero of=/dev/null bs=1M count=200
'

sleep 2
echo "Memory stats:"
docker stats --no-stream mem-test

# CPU limit test
echo -e "\n[CPU Limit Test]"
echo "Starting container with 0.5 CPU limit..."
docker run -d --name cpu-test --cpus="0.5" --rm alpine sh -c '
    echo "CPU stress test...";
    while true; do echo "scale=5000; a(1)*4" | bc -l >/dev/null; done
'

sleep 5
echo "CPU stats:"
docker stats --no-stream cpu-test

# PID limit test
echo -e "\n[PID Limit Test]"
echo "Starting container with PID limit of 10..."
docker run -d --name pid-test --pids-limit=10 --rm alpine sh -c '
    echo "Attempting to create many processes...";
    for i in $(seq 1 20); do
        sleep 100 &
        echo "Started process $i (PID: $!)"
    done;
    ps aux
'

sleep 2
echo "Process count in container:"
docker exec pid-test sh -c "ps aux | wc -l"

# Show cgroup paths
echo -e "\n[Cgroup Paths]"
CONTAINER_ID=$(docker inspect -f '{{.Id}}' mem-test 2>/dev/null)
if [ ! -z "$CONTAINER_ID" ]; then
    echo "Memory cgroup: /sys/fs/cgroup/memory/docker/$CONTAINER_ID/"
    sudo cat /sys/fs/cgroup/memory/docker/$CONTAINER_ID/memory.limit_in_bytes 2>/dev/null || echo "Need sudo to view"
fi

# Cleanup
docker stop mem-test cpu-test pid-test 2>/dev/null

# Demonstrate DoS prevention
echo -e "\n[DoS Prevention Demo]"
echo "Starting fork bomb in limited container..."
docker run -d --name fork-bomb --pids-limit=50 --memory=64m --rm alpine sh -c '
    :(){ :|:& };:
'

sleep 3
echo "Container still running: $(docker ps -q -f name=fork-bomb | wc -l)"
echo "Host still responsive!"

docker stop fork-bomb 2>/dev/null
EOF

chmod +x test-cgroups.sh
./test-cgroups.sh
```

### Section 3.2: Linux Security Modules for Containers (75 minutes)

Based on Docker's support for existing, well-known systems like AppArmor, SELinux, and other kernel security features, let's implement comprehensive security profiles.

### Lab 3.2: Implementing Security Profiles

**Exercise 1: AppArmor Profiles for Docker**

```bash
cd ~/docker-security-labs/module3/lab2

# Check AppArmor status
sudo aa-status

# Examine Docker's default AppArmor profile
sudo cat /etc/apparmor.d/docker-default

# Create custom AppArmor profile for a web application
sudo tee /etc/apparmor.d/docker-webapp << 'EOF'
#include <tunables/global>

profile docker-webapp flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Network access
  network inet tcp,
  network inet udp,
  network inet icmp,
  
  # Deny network raw
  deny network raw,

  # File access
  # Allow read to necessary paths
  /etc/ld.so.cache r,
  /lib/** r,
  /usr/lib/** r,
  /proc/sys/kernel/random/uuid r,
  /proc/sys/kernel/random/boot_id r,
  
  # App specific
  /app/** r,
  /app/data/** rw,
  
  # Temp files
  /tmp/** rw,
  /var/tmp/** rw,
  
  # Deny access to sensitive files
  deny /etc/passwd r,
  deny /etc/shadow r,
  deny /etc/ssh/* r,
  deny /root/** rw,
  deny /home/** rw,
  
  # Deny dangerous capabilities
  deny capability dac_override,
  deny capability dac_read_search,
  deny capability setuid,
  deny capability setgid,
  deny capability net_admin,
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability sys_ptrace,
  deny capability sys_chroot,
  deny capability mknod,
  deny capability audit_write,
  deny capability setfcap,

  # Allow signal from Docker daemon
  signal (receive) peer=unconfined,
  
  # Deny ptrace
  deny ptrace,

  # Deny mount
  deny mount,
  deny umount,
  
  # Allow pivot_root for container startup
  pivot_root,
}
EOF

# Load the profile
sudo apparmor_parser -r /etc/apparmor.d/docker-webapp

# Test application with different profiles
cat > webapp.py << 'EOF'
#!/usr/bin/env python3
import os
import socket
import http.server
import socketserver

class SecurityTestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        
        tests = []
        
        # Test file access
        try:
            with open('/etc/passwd', 'r') as f:
                f.read()
            tests.append("✗ SECURITY RISK: Can read /etc/passwd")
        except:
            tests.append("✓ PROTECTED: Cannot read /etc/passwd")
        
        # Test network raw socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            tests.append("✗ SECURITY RISK: Can create raw sockets")
        except:
            tests.append("✓ PROTECTED: Cannot create raw sockets")
        
        # Test capability
        try:
            os.setuid(0)
            tests.append("✗ SECURITY RISK: Can change UID")
        except:
            tests.append("✓ PROTECTED: Cannot change UID")
        
        response = "<h1>Security Test Results</h1><ul>"
        for test in tests:
            response += f"<li>{test}</li>"
        response += "</ul>"
        
        self.wfile.write(response.encode())

PORT = 8000
with socketserver.TCPServer(("", PORT), SecurityTestHandler) as httpd:
    print(f"Server running on port {PORT}")
    httpd.serve_forever()
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
COPY webapp.py .
EXPOSE 8000
CMD ["python", "webapp.py"]
EOF

# Build and run with different profiles
docker build -t webapp-test .

echo "=== Testing without AppArmor ==="
docker run -d --name test-unconfined -p 8001:8000 --security-opt apparmor=unconfined webapp-test
sleep 2
curl -s http://localhost:8001 | grep -E "(RISK|PROTECTED)"
docker stop test-unconfined && docker rm test-unconfined

echo -e "\n=== Testing with docker-default profile ==="
docker run -d --name test-default -p 8002:8000 webapp-test
sleep 2
curl -s http://localhost:8002 | grep -E "(RISK|PROTECTED)"
docker stop test-default && docker rm test-default

echo -e "\n=== Testing with custom webapp profile ==="
docker run -d --name test-webapp -p 8003:8000 --security-opt apparmor=docker-webapp webapp-test
sleep 2
curl -s http://localhost:8003 | grep -E "(RISK|PROTECTED)"
docker stop test-webapp && docker rm test-webapp
```

**Exercise 2: Seccomp Profiles**

```bash
# Create comprehensive seccomp profile
cat > webapp-seccomp.json << 'EOF'
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "archMap": [
        {
            "architecture": "SCMP_ARCH_X86_64",
            "subArchitectures": [
                "SCMP_ARCH_X86",
                "SCMP_ARCH_X32"
            ]
        }
    ],
    "syscalls": [
        {
            "names": [
                "accept",
                "accept4",
                "access",
                "adjtimex",
                "alarm",
                "arch_prctl",
                "bind",
                "brk",
                "clock_adjtime",
                "clock_getres",
                "clock_gettime",
                "clock_nanosleep",
                "clone",
                "close",
                "connect",
                "copy_file_range",
                "dup",
                "dup2",
                "dup3",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_ctl_old",
                "epoll_pwait",
                "epoll_wait",
                "epoll_wait_old",
                "eventfd",
                "eventfd2",
                "execve",
                "execveat",
                "exit",
                "exit_group",
                "faccessat",
                "faccessat2",
                "fadvise64",
                "fallocate",
                "fanotify_mark",
                "fchdir",
                "fchmod",
                "fchmodat",
                "fchown",
                "fchown32",
                "fchownat",
                "fcntl",
                "fcntl64",
                "fdatasync",
                "fgetxattr",
                "flistxattr",
                "flock",
                "fork",
                "fremovexattr",
                "fsetxattr",
                "fstat",
                "fstat64",
                "fstatat64",
                "fstatfs",
                "fstatfs64",
                "fsync",
                "ftruncate",
                "ftruncate64",
                "futex",
                "futimesat",
                "get_robust_list",
                "get_thread_area",
                "getcpu",
                "getcwd",
                "getdents",
                "getdents64",
                "getegid",
                "getegid32",
                "geteuid",
                "geteuid32",
                "getgid",
                "getgid32",
                "getgroups",
                "getgroups32",
                "getitimer",
                "getpeername",
                "getpgid",
                "getpgrp",
                "getpid",
                "getppid",
                "getpriority",
                "getrandom",
                "getresgid",
                "getresgid32",
                "getresuid",
                "getresuid32",
                "getrlimit",
                "getrusage",
                "getsid",
                "getsockname",
                "getsockopt",
                "gettid",
                "gettimeofday",
                "getuid",
                "getuid32",
                "getxattr",
                "inotify_add_watch",
                "inotify_init",
                "inotify_init1",
                "inotify_rm_watch",
                "io_cancel",
                "io_destroy",
                "io_getevents",
                "io_setup",
                "io_submit",
                "ioctl",
                "ioprio_get",
                "ioprio_set",
                "kill",
                "lgetxattr",
                "link",
                "linkat",
                "listen",
                "listxattr",
                "llistxattr",
                "lremovexattr",
                "lseek",
                "lsetxattr",
                "lstat",
                "lstat64",
                "madvise",
                "memfd_create",
                "mincore",
                "mkdir",
                "mkdirat",
                "mlock",
                "mlock2",
                "mlockall",
                "mmap",
                "mmap2",
                "mprotect",
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedsend",
                "mq_unlink",
                "mremap",
                "msgctl",
                "msgget",
                "msgrcv",
                "msgsnd",
                "msync",
                "munlock",
                "munlockall",
                "munmap",
                "nanosleep",
                "newfstatat",
                "open",
                "openat",
                "openat2",
                "pause",
                "pipe",
                "pipe2",
                "poll",
                "ppoll",
                "prctl",
                "pread64",
                "preadv",
                "preadv2",
                "prlimit64",
                "pselect6",
                "pwrite64",
                "pwritev",
                "pwritev2",
                "read",
                "readahead",
                "readlink",
                "readlinkat",
                "readv",
                "recv",
                "recvfrom",
                "recvmmsg",
                "recvmsg",
                "remap_file_pages",
                "removexattr",
                "rename",
                "renameat",
                "renameat2",
                "restart_syscall",
                "rmdir",
                "rt_sigaction",
                "rt_sigpending",
                "rt_sigprocmask",
                "rt_sigqueueinfo",
                "rt_sigreturn",
                "rt_sigsuspend",
                "rt_sigtimedwait",
                "rt_tgsigqueueinfo",
                "sched_get_priority_max",
                "sched_get_priority_min",
                "sched_getaffinity",
                "sched_getattr",
                "sched_getparam",
                "sched_getscheduler",
                "sched_rr_get_interval",
                "sched_setaffinity",
                "sched_setattr",
                "sched_setparam",
                "sched_setscheduler",
                "sched_yield",
                "seccomp",
                "select",
                "semctl",
                "semget",
                "semop",
                "semtimedop",
                "send",
                "sendfile",
                "sendfile64",
                "sendmmsg",
                "sendmsg",
                "sendto",
                "set_robust_list",
                "set_thread_area",
                "set_tid_address",
                "setfsgid",
                "setfsgid32",
                "setfsuid",
                "setfsuid32",
                "setgid",
                "setgid32",
                "setgroups",
                "setgroups32",
                "setitimer",
                "setpgid",
                "setpriority",
                "setregid",
                "setregid32",
                "setresgid",
                "setresgid32",
                "setresuid",
                "setresuid32",
                "setreuid",
                "setreuid32",
                "setrlimit",
                "setsid",
                "setsockopt",
                "setuid",
                "setuid32",
                "setxattr",
                "shmat",
                "shmctl",
                "shmdt",
                "shmget",
                "shutdown",
                "sigaltstack",
                "signalfd",
                "signalfd4",
                "socket",
                "socketcall",
                "socketpair",
                "splice",
                "stat",
                "stat64",
                "statfs",
                "statfs64",
                "statx",
                "symlink",
                "symlinkat",
                "sync",
                "sync_file_range",
                "syncfs",
                "tee",
                "tgkill",
                "time",
                "timer_create",
                "timer_delete",
                "timer_getoverrun",
                "timer_gettime",
                "timer_gettime64",
                "timer_settime",
                "timer_settime64",
                "timerfd_create",
                "timerfd_gettime",
                "timerfd_gettime64",
                "timerfd_settime",
                "timerfd_settime64",
                "times",
                "tkill",
                "truncate",
                "truncate64",
                "ugetrlimit",
                "umask",
                "uname",
                "unlink",
                "unlinkat",
                "unshare",
                "utime",
                "utimensat",
                "utimensat_time64",
                "utimes",
                "vfork",
                "wait4",
                "waitid",
                "waitpid",
                "write",
                "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "names": [
                "clone"
            ],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 2114060288,
                    "op": "SCMP_CMP_MASKED_EQ"
                }
            ],
            "comment": "Allow clone for threads"
        }
    ]
}
EOF

# Test seccomp restrictions
cat > seccomp-test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

void test_syscall(const char* name, int result) {
    if (result == 0) {
        printf("✗ SECURITY RISK: %s succeeded\n", name);
    } else {
        printf("✓ PROTECTED: %s blocked\n", name);
    }
}

int main() {
    printf("=== Seccomp Security Test ===\n\n");
    
    // Test mount (should be blocked)
    int mount_result = mount("none", "/mnt", "tmpfs", 0, "");
    test_syscall("mount()", mount_result);
    
    // Test ptrace (should be blocked)
    int ptrace_result = ptrace(PTRACE_TRACEME, 0, 0, 0);
    test_syscall("ptrace()", ptrace_result);
    
    // Test raw socket (should be blocked)
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    test_syscall("socket(RAW)", raw_sock < 0 ? -1 : 0);
    if (raw_sock >= 0) close(raw_sock);
    
    // Test regular socket (should work)
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    printf("%s: Regular TCP socket\n", tcp_sock >= 0 ? "✓ ALLOWED" : "✗ BLOCKED");
    if (tcp_sock >= 0) close(tcp_sock);
    
    // Test system time change (should be blocked)
    struct timespec ts = {0, 0};
    int time_result = clock_settime(CLOCK_REALTIME, &ts);
    test_syscall("clock_settime()", time_result);
    
    return 0;
}
EOF

# Compile test program
docker run --rm -v $(pwd):/work -w /work gcc:latest gcc -o seccomp-test seccomp-test.c

# Test with and without seccomp
echo "=== Testing WITHOUT seccomp (insecure) ==="
docker run --rm --privileged --security-opt seccomp=unconfined \
    -v $(pwd)/seccomp-test:/seccomp-test alpine /seccomp-test

echo -e "\n=== Testing WITH default Docker seccomp ==="
docker run --rm -v $(pwd)/seccomp-test:/seccomp-test alpine /seccomp-test

echo -e "\n=== Testing WITH custom strict seccomp ==="
docker run --rm --security-opt seccomp=$(pwd)/webapp-seccomp.json \
    -v $(pwd)/seccomp-test:/seccomp-test alpine /seccomp-test
```

### Section 3.3: User Namespaces and Rootless Docker (60 minutes)

As of Docker 1.10, User Namespaces are supported directly by the docker daemon. This feature allows for the root user in a container to be mapped to a non uid-0 user outside the container.

### Lab 3.3: Implementing User Namespaces

**Exercise 1: || echo "No privileged containers found"
        
        # Check resource usage
        echo -e "\n[Checking container resource usage]"
        docker stats --no-stream --format \
            "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
        
        # Check for containers with Docker socket
        echo -e "\n[Checking for Docker socket mounts]"
        docker ps -q | while read container; do
            if docker inspect $container | grep -q "/var/run/docker.sock"; then
                echo "WARNING: Container $(docker inspect -f '{{.Name}}' $container) has Docker socket mounted!"
            fi
        done
        ;;
        
    isolate)
        CONTAINER=$2
        if [ -z "$CONTAINER" ]; then
            echo "Usage: $0 isolate <container_name>"
            exit 1
        fi
        
        echo "=== Isolating Container: $CONTAINER ==="
        
        # Create incident directory
        mkdir -p "$INCIDENT_DIR"
        
        # Pause container to preserve state
        echo "Pausing container..."
        docker pause $CONTAINER
        
        # Disconnect from networks
        echo "Disconnecting from networks..."
        docker network disconnect bridge $CONTAINER 2>/dev/null || true
        
        # Create forensic image
        echo "Creating forensic image..."
        docker commit $CONTAINER "incident-$CONTAINER-$(date +%s)"
        
        echo "Container isolated. Incident data in: $INCIDENT_DIR"
        ;;
        
    collect)
        CONTAINER=$2
        if [ -z "$CONTAINER" ]; then
            echo "Usage: $0 collect <container_name>"
            exit 1
        fi
        
        echo "=== Collecting Forensic Data: $CONTAINER ==="
        
        mkdir -p "$INCIDENT_DIR"
        cd "$INCIDENT_DIR"
        
        # Container configuration
        echo "Collecting container configuration..."
        docker inspect $CONTAINER > container-inspect.json
        
        # Container logs
        echo "Collecting container logs..."
        docker logs $CONTAINER > container.log 2>&1
        
        # Running processes
        echo "Collecting process information..."
        docker top $CONTAINER > processes.txt
        
        # File system changes
        echo "Collecting filesystem changes..."
        docker diff $CONTAINER > filesystem-diff.txt
        
        # Network connections
        echo "Collecting network information..."
        docker exec $CONTAINER sh -c 'netstat -tuln 2>/dev/null || ss -tuln' \
            > network-connections.txt 2>/dev/null || \
            echo "Unable to collect network info" > network-connections.txt
        
        # Environment variables
        echo "Collecting environment variables..."
        docker exec $CONTAINER env > environment.txt 2>/dev/null || \
            echo "Unable to collect environment" > environment.txt
        
        # Container metadata
        echo "Collecting metadata..."
        cat > metadata.txt << META
Incident Time: $(date)
Container ID: $(docker inspect -f '{{.Id}}' $CONTAINER)
Container Name: $CONTAINER
Image: $(docker inspect -f '{{.Config.Image}}' $CONTAINER)
Created: $(docker inspect -f '{{.Created}}' $CONTAINER)
Started: $(docker inspect -f '{{.State.StartedAt}}' $CONTAINER)
User: $(docker inspect -f '{{.Config.User}}' $CONTAINER)
Privileged: $(docker inspect -f '{{.HostConfig.Privileged}}' $CONTAINER)
META
        
        echo "Forensic data collected in: $INCIDENT_DIR"
        cd - > /dev/null
        ;;
        
    analyze)
        CONTAINER=$2
        if [ -z "$CONTAINER" ]; then
            echo "Usage: $0 analyze <container_name>"
            exit 1
        fi
        
        echo "=== Analyzing Container: $CONTAINER ==="
        
        # Security configuration analysis
        echo -e "\n[Security Configuration]"
        docker inspect $CONTAINER --format '
Privileged: {{.HostConfig.Privileged}}
User: {{.Config.User}}
ReadOnly: {{.HostConfig.ReadonlyRootfs}}
NoNewPrivileges: {{.HostConfig.SecurityOpt}}
Capabilities Added: {{.HostConfig.CapAdd}}
Capabilities Dropped: {{.HostConfig.CapDrop}}'
        
        # Resource usage analysis
        echo -e "\n[Resource Usage]"
        docker stats --no-stream $CONTAINER
        
        # Network analysis
        echo -e "\n[Network Configuration]"
        docker inspect $CONTAINER --format '
Network Mode: {{.HostConfig.NetworkMode}}
Published Ports: {{.NetworkSettings.Ports}}'
        
        # Mount analysis
        echo -e "\n[Volume Mounts]"
        docker inspect $CONTAINER --format '{{range .Mounts}}
Source: {{.Source}}
Destination: {{.Destination}}
Mode: {{.Mode}}
{{end}}'
        
        # Recent logs analysis
        echo -e "\n[Recent Log Activity]"
        docker logs --tail 50 $CONTAINER 2>&1 | \
            grep -iE "(error|fail|attack|exploit|malicious|unauthorized)" || \
            echo "No suspicious log entries found"
        ;;
        
    remediate)
        echo "=== Docker Security Remediation ==="
        
        # List all running containers
        echo -e "\n[Current Running Containers]"
        docker ps
        
        # Recommendations
        echo -e "\n[Security Recommendations]"
        cat << RECOMMENDATIONS
1. Stop and remove suspicious containers:
   docker stop <container> && docker rm <container>

2. Remove compromised images:
   docker rmi <image>

3. Update security policies:
   - Enable user namespace remapping
   - Implement AppArmor/SELinux profiles
   - Use read-only root filesystems
   - Drop all unnecessary capabilities

4. Implement runtime monitoring:
   - Deploy Falco or similar tools
   - Enable Docker audit logging
   - Set up alerts for suspicious activity

5. Review and update:
   - Review all running containers
   - Update base images
   - Scan for vulnerabilities
   - Implement least privilege principles
RECOMMENDATIONS
        ;;
        
    *)
        echo "Docker Incident Response Toolkit"
        echo "Usage: $0 {detect|isolate|collect|analyze|remediate} [container_name]"
        echo ""
        echo "Commands:"
        echo "  detect     - Detect security issues in running containers"
        echo "  isolate    - Isolate a suspicious container"
        echo "  collect    - Collect forensic data from a container"
        echo "  analyze    - Analyze a container's security configuration"
        echo "  remediate  - Show remediation recommendations"
        exit 1
        ;;
esac
EOF

chmod +x docker-incident-response.sh

# Demonstrate incident response workflow
echo "=== Demonstrating Incident Response Workflow ==="

# Create a "compromised" container for demonstration
docker run -d --name compromised-demo \
    --privileged \
    -v /:/host \
    alpine sh -c '
        # Simulate malicious activity
        echo "mining cryptocurrency..." > /tmp/miner.log
        while true; do
            echo "$(date): mining block..." >> /tmp/miner.log
            sleep 5
        done
    '

# Run through incident response steps
echo -e "\n[Step 1: Detection]"
./docker-incident-response.sh detect

echo -e "\n[Step 2: Analysis]"
./docker-incident-response.sh analyze compromised-demo

echo -e "\n[Step 3: Collection]"
./docker-incident-response.sh collect compromised-demo

echo -e "\n[Step 4: Isolation]"
./docker-incident-response.sh isolate compromised-demo

echo -e "\n[Step 5: Remediation]"
./docker-incident-response.sh remediate

# Cleanup
docker unpause compromised-demo 2>/dev/null
docker stop compromised-demo
docker rm compromised-demo
```

### Section 3.5: Container Hardening Best Practices (60 minutes)

Based on Docker's security recommendations, let's implement comprehensive hardening strategies.

### Lab 3.5: Implementing Defense in Depth

**Exercise 1: Create Hardened Container Template**

```bash
cd ~/docker-security-labs/module3/lab5

# Create a hardened base image builder
cat > create-hardened-base.sh << 'EOF'
#!/bin/bash

# Hardened Base Image Creator
# Implements Docker security best practices

IMAGE_NAME=${1:-hardened-alpine}
VERSION=${2:-latest}

# Create build directory
mkdir -p hardened-build
cd hardened-build

# Create hardened Dockerfile
cat > Dockerfile << 'DOCKERFILE'
# Start with minimal base
FROM alpine:3.18

# Update and patch
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
        ca-certificates \
        tzdata && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 10001 -S appgroup && \
    adduser -u 10001 -S -G appgroup -h /app appuser

# Remove unnecessary tools
RUN rm -rf /usr/bin/wget \
           /usr/bin/curl \
           /bin/ping \
           /bin/nc \
           /usr/bin/nslookup

# Set up directories with proper permissions
RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app && \
    chmod -R 550 /app && \
    chmod -R 770 /app/data

# Security labels
LABEL security.scan="true" \
      security.nonroot="true" \
      security.updates="auto"

# Switch to non-root user
USER appuser
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD echo "OK" || exit 1

# Default entrypoint
ENTRYPOINT ["/bin/sh"]
DOCKERFILE

# Build the hardened base image
echo "Building hardened base image..."
docker build -t $IMAGE_NAME:$VERSION .

# Create security scanning script
cat > ../scan-hardened-image.sh << 'SCRIPT'# Module 3: Runtime Security and Container Hardening (Revised)

## Module Overview
Duration: 5 hours  
Format: Video lectures (2 hours), Hands-on labs (2.5 hours), Assessment (30 minutes)

## Learning Objectives
By the end of this module, you will be able to:
- Configure and implement Linux kernel security features for containers (capabilities, namespaces, cgroups)
- Deploy and manage security profiles using AppArmor, SELinux, and seccomp
- Implement user namespace remapping to prevent privilege escalation
- Monitor container runtime behavior and detect anomalies
- Respond effectively to container security incidents
- Apply defense-in-depth strategies to harden containers

---

## Section 3.1: Docker Security Architecture and Kernel Features (60 minutes)

### Video Lecture: Understanding Docker's Security Model

Based on Docker's official security documentation, there are four major areas to consider when reviewing Docker security: the intrinsic security of the kernel and its support for namespaces and cgroups, the attack surface of the Docker daemon itself, loopholes in the container configuration profile, and the "hardening" security features of the kernel.

#### The Four Pillars of Docker Security

1. **Kernel Security Features**
   - Namespaces for isolation
   - Control groups for resource management
   - Capabilities for privilege management

2. **Docker Daemon Security**
   - Attack surface considerations
   - Socket security
   - API endpoint protection

3. **Container Configuration**
   - Default vs. custom profiles
   - Security options and flags
   - Image security

4. **Kernel Hardening**
   - LSMs (AppArmor, SELinux)
   - Seccomp filtering
   - User namespaces

### Lab 3.1: Exploring Docker's Security Foundations

**Setup:**
```bash
mkdir -p ~/docker-security-labs/module3/lab1
cd ~/docker-security-labs/module3/lab1

# Verify kernel support for security features
cat > check-security.sh << 'EOF'
#!/bin/bash
echo "=== Docker Security Feature Check ==="

# Check kernel version
echo -e "\n[Kernel Version]"
uname -r

# Check namespace support
echo -e "\n[Namespace Support]"
ls -la /proc/self/ns/

# Check for user namespaces
echo -e "\n[User Namespace Support]"
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
    echo "User namespaces: $(cat /proc/sys/kernel/unprivileged_userns_clone)"
else
    echo "User namespaces: Checking alternative method..."
    grep CONFIG_USER_NS /boot/config-$(uname -r) || echo "Not found in kernel config"
fi

# Check security modules
echo -e "\n[Security Modules]"
if [ -f /sys/kernel/security/lsm ]; then
    echo "Active LSMs: $(cat /sys/kernel/security/lsm)"
fi

# Check AppArmor
if command -v aa-status &> /dev/null; then
    echo "AppArmor: Available"
    sudo aa-status --summary 2>/dev/null || echo "AppArmor: Permission needed for status"
else
    echo "AppArmor: Not installed"
fi

# Check SELinux
if command -v getenforce &> /dev/null; then
    echo "SELinux: $(getenforce)"
else
    echo "SELinux: Not installed"
fi

# Check Docker info
echo -e "\n[Docker Security Info]"
docker info --format '{{json .SecurityOptions}}' | jq . 2>/dev/null || docker info | grep -A5 "Security Options"

# Check default capabilities
echo -e "\n[Default Docker Capabilities]"
docker run --rm alpine sh -c 'apk add -q libcap 2>/dev/null && capsh --print | grep Current' || echo "Unable to check capabilities"
EOF

chmod +x check-security.sh
./check-security.sh
```

**Exercise 1: Understanding Capabilities**

By default, Docker starts containers with a restricted set of capabilities. Docker drops all capabilities except those needed, using an allowlist instead of a denylist approach.

```bash
# Create capability test script
cat > test-capabilities.sh << 'EOF'
#!/bin/sh
echo "=== Testing Docker Capability Restrictions ==="

# Function to test capability
test_cap() {
    local cap=$1
    local test_cmd=$2
    local desc=$3
    
    echo -e "\n[$cap] $desc"
    if eval $test_cmd 2>/dev/null; then
        echo "✓ SUCCESS: Capability available"
    else
        echo "✗ BLOCKED: Capability dropped (Good for security!)"
    fi
}

# Test various capabilities
test_cap "CAP_NET_BIND_SERVICE" "nc -l -p 80 &" "Bind to privileged port"
test_cap "CAP_SYS_ADMIN" "mount -t tmpfs tmpfs /mnt" "Mount filesystems"
test_cap "CAP_SYS_MODULE" "modprobe dummy" "Load kernel modules"
test_cap "CAP_SYS_TIME" "date -s '2030-01-01'" "Change system time"
test_cap "CAP_NET_RAW" "ping -c 1 google.com" "Use raw sockets"
test_cap "CAP_MKNOD" "mknod /tmp/test c 1 3" "Create device nodes"
test_cap "CAP_AUDIT_WRITE" "logger test" "Write audit logs"
test_cap "CAP_SETFCAP" "setcap cap_net_raw+p /bin/ping" "Set file capabilities"

# Show current capabilities
echo -e "\n[Current Capabilities]"
cat /proc/1/status | grep ^Cap
EOF

# Test with default capabilities
echo "=== Testing with DEFAULT Docker capabilities ==="
docker run --rm -v $(pwd)/test-capabilities.sh:/test.sh:ro alpine sh /test.sh

# Test with additional capabilities
echo -e "\n=== Testing with ADDED capabilities (less secure) ==="
docker run --rm --cap-add SYS_ADMIN --cap-add SYS_TIME \
    -v $(pwd)/test-capabilities.sh:/test.sh:ro alpine sh /test.sh

# Test with all capabilities dropped
echo -e "\n=== Testing with ALL capabilities dropped (most secure) ==="
docker run --rm --cap-drop ALL \
    -v $(pwd)/test-capabilities.sh:/test.sh:ro alpine sh /test.sh
```

**Exercise 2: Namespace Isolation**

When you start a container with docker run, behind the scenes Docker creates a set of namespaces and control groups for the container. Namespaces provide the first and most straightforward form of isolation.

```bash
# Create namespace exploration script
cat > explore-namespaces.sh << 'EOF'
#!/bin/bash

echo "=== Exploring Docker Namespace Isolation ==="

# Function to show namespace info
show_ns_info() {
    local container=$1
    local pid=$(docker inspect -f '{{.State.Pid}}' $container 2>/dev/null)
    
    if [ -z "$pid" ] || [ "$pid" = "0" ]; then
        echo "Container not running or PID not found"
        return
    fi
    
    echo -e "\nContainer: $container (PID: $pid)"
    echo "Namespaces:"
    sudo ls -la /proc/$pid/ns/ 2>/dev/null || echo "Need sudo to view namespaces"
}

# Start test containers
docker run -d --name ns-test1 --rm alpine sleep 300
docker run -d --name ns-test2 --rm alpine sleep 300

# Show host namespaces
echo "Host Namespaces:"
ls -la /proc/self/ns/

# Show container namespaces
show_ns_info ns-test1
show_ns_info ns-test2

# Compare namespace IDs
echo -e "\n=== Namespace Isolation Verification ==="
NS1_PID=$(docker inspect -f '{{.State.Pid}}' ns-test1)
NS2_PID=$(docker inspect -f '{{.State.Pid}}' ns-test2)

if [ ! -z "$NS1_PID" ] && [ ! -z "$NS2_PID" ]; then
    echo "Comparing PID namespaces:"
    echo "Container 1: $(sudo readlink /proc/$NS1_PID/ns/pid 2>/dev/null || echo 'Need sudo')"
    echo "Container 2: $(sudo readlink /proc/$NS2_PID/ns/pid 2>/dev/null || echo 'Need sudo')"
    echo "Host:        $(readlink /proc/self/ns/pid)"
fi

# Test process isolation
echo -e "\n=== Process Isolation Test ==="
echo "Processes visible in container 1:"
docker exec ns-test1 ps aux

echo -e "\nProcesses visible on host:"
ps aux | wc -l

# Cleanup
docker stop ns-test1 ns-test2 2>/dev/null
EOF

chmod +x explore-namespaces.sh
./explore-namespaces.sh
```

**Exercise 3: Control Groups (cgroups)**

Control Groups are another key component of Linux containers. They implement resource accounting and limiting... they are essential to fend off some denial-of-service attacks.

```bash
# Create cgroup testing script
cat > test-cgroups.sh << 'EOF'
#!/bin/bash

echo "=== Testing Docker Control Groups (cgroups) ==="

# Memory limit test
echo -e "\n[Memory Limit Test]"
echo "Starting container with 128MB memory limit..."
docker run -d --name mem-test --memory="128m" --rm alpine sh -c '
    echo "Allocating memory...";
    dd if=/dev/zero of=/dev/null bs=1M count=200
'

sleep 2
echo "Memory stats:"
docker stats --no-stream mem-test

# CPU limit test
echo -e "\n[CPU Limit Test]"
echo "Starting container with 0.5 CPU limit..."
docker run -d --name cpu-test --cpus="0.5" --rm alpine sh -c '
    echo "CPU stress test...";
    while true; do echo "scale=5000; a(1)*4" | bc -l >/dev/null; done
'

sleep 5
echo "CPU stats:"
docker stats --no-stream cpu-test

# PID limit test
echo -e "\n[PID Limit Test]"
echo "Starting container with PID limit of 10..."
docker run -d --name pid-test --pids-limit=10 --rm alpine sh -c '
    echo "Attempting to create many processes...";
    for i in $(seq 1 20); do
        sleep 100 &
        echo "Started process $i (PID: $!)"
    done;
    ps aux
'

sleep 2
echo "Process count in container:"
docker exec pid-test sh -c "ps aux | wc -l"

# Show cgroup paths
echo -e "\n[Cgroup Paths]"
CONTAINER_ID=$(docker inspect -f '{{.Id}}' mem-test 2>/dev/null)
if [ ! -z "$CONTAINER_ID" ]; then
    echo "Memory cgroup: /sys/fs/cgroup/memory/docker/$CONTAINER_ID/"
    sudo cat /sys/fs/cgroup/memory/docker/$CONTAINER_ID/memory.limit_in_bytes 2>/dev/null || echo "Need sudo to view"
fi

# Cleanup
docker stop mem-test cpu-test pid-test 2>/dev/null

# Demonstrate DoS prevention
echo -e "\n[DoS Prevention Demo]"
echo "Starting fork bomb in limited container..."
docker run -d --name fork-bomb --pids-limit=50 --memory=64m --rm alpine sh -c '
    :(){ :|:& };:
'

sleep 3
echo "Container still running: $(docker ps -q -f name=fork-bomb | wc -l)"
echo "Host still responsive!"

docker stop fork-bomb 2>/dev/null
EOF

chmod +x test-cgroups.sh
./test-cgroups.sh
```

### Section 3.2: Linux Security Modules for Containers (75 minutes)

Based on Docker's support for existing, well-known systems like AppArmor, SELinux, and other kernel security features, let's implement comprehensive security profiles.

### Lab 3.2: Implementing Security Profiles

**Exercise 1: AppArmor Profiles for Docker**

```bash
cd ~/docker-security-labs/module3/lab2

# Check AppArmor status
sudo aa-status

# Examine Docker's default AppArmor profile
sudo cat /etc/apparmor.d/docker-default

# Create custom AppArmor profile for a web application
sudo tee /etc/apparmor.d/docker-webapp << 'EOF'
#include <tunables/global>

profile docker-webapp flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  # Network access
  network inet tcp,
  network inet udp,
  network inet icmp,
  
  # Deny network raw
  deny network raw,

  # File access
  # Allow read to necessary paths
  /etc/ld.so.cache r,
  /lib/** r,
  /usr/lib/** r,
  /proc/sys/kernel/random/uuid r,
  /proc/sys/kernel/random/boot_id r,
  
  # App specific
  /app/** r,
  /app/data/** rw,
  
  # Temp files
  /tmp/** rw,
  /var/tmp/** rw,
  
  # Deny access to sensitive files
  deny /etc/passwd r,
  deny /etc/shadow r,
  deny /etc/ssh/* r,
  deny /root/** rw,
  deny /home/** rw,
  
  # Deny dangerous capabilities
  deny capability dac_override,
  deny capability dac_read_search,
  deny capability setuid,
  deny capability setgid,
  deny capability net_admin,
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability sys_ptrace,
  deny capability sys_chroot,
  deny capability mknod,
  deny capability audit_write,
  deny capability setfcap,

  # Allow signal from Docker daemon
  signal (receive) peer=unconfined,
  
  # Deny ptrace
  deny ptrace,

  # Deny mount
  deny mount,
  deny umount,
  
  # Allow pivot_root for container startup
  pivot_root,
}
EOF

# Load the profile
sudo apparmor_parser -r /etc/apparmor.d/docker-webapp

# Test application with different profiles
cat > webapp.py << 'EOF'
#!/usr/bin/env python3
import os
import socket
import http.server
import socketserver

class SecurityTestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        
        tests = []
        
        # Test file access
        try:
            with open('/etc/passwd', 'r') as f:
                f.read()
            tests.append("✗ SECURITY RISK: Can read /etc/passwd")
        except:
            tests.append("✓ PROTECTED: Cannot read /etc/passwd")
        
        # Test network raw socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            tests.append("✗ SECURITY RISK: Can create raw sockets")
        except:
            tests.append("✓ PROTECTED: Cannot create raw sockets")
        
        # Test capability
        try:
            os.setuid(0)
            tests.append("✗ SECURITY RISK: Can change UID")
        except:
            tests.append("✓ PROTECTED: Cannot change UID")
        
        response = "<h1>Security Test Results</h1><ul>"
        for test in tests:
            response += f"<li>{test}</li>"
        response += "</ul>"
        
        self.wfile.write(response.encode())

PORT = 8000
with socketserver.TCPServer(("", PORT), SecurityTestHandler) as httpd:
    print(f"Server running on port {PORT}")
    httpd.serve_forever()
EOF

# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
COPY webapp.py .
EXPOSE 8000
CMD ["python", "webapp.py"]
EOF

# Build and run with different profiles
docker build -t webapp-test .

echo "=== Testing without AppArmor ==="
docker run -d --name test-unconfined -p 8001:8000 --security-opt apparmor=unconfined webapp-test
sleep 2
curl -s http://localhost:8001 | grep -E "(RISK|PROTECTED)"
docker stop test-unconfined && docker rm test-unconfined

echo -e "\n=== Testing with docker-default profile ==="
docker run -d --name test-default -p 8002:8000 webapp-test
sleep 2
curl -s http://localhost:8002 | grep -E "(RISK|PROTECTED)"
docker stop test-default && docker rm test-default

echo -e "\n=== Testing with custom webapp profile ==="
docker run -d --name test-webapp -p 8003:8000 --security-opt apparmor=docker-webapp webapp-test
sleep 2
curl -s http://localhost:8003 | grep -E "(RISK|PROTECTED)"
docker stop test-webapp && docker rm test-webapp
```

**Exercise 2: Seccomp Profiles**

```bash
# Create comprehensive seccomp profile
cat > webapp-seccomp.json << 'EOF'
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "archMap": [
        {
            "architecture": "SCMP_ARCH_X86_64",
            "subArchitectures": [
                "SCMP_ARCH_X86",
                "SCMP_ARCH_X32"
            ]
        }
    ],
    "syscalls": [
        {
            "names": [
                "accept",
                "accept4",
                "access",
                "adjtimex",
                "alarm",
                "arch_prctl",
                "bind",
                "brk",
                "clock_adjtime",
                "clock_getres",
                "clock_gettime",
                "clock_nanosleep",
                "clone",
                "close",
                "connect",
                "copy_file_range",
                "dup",
                "dup2",
                "dup3",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_ctl_old",
                "epoll_pwait",
                "epoll_wait",
                "epoll_wait_old",
                "eventfd",
                "eventfd2",
                "execve",
                "execveat",
                "exit",
                "exit_group",
                "faccessat",
                "faccessat2",
                "fadvise64",
                "fallocate",
                "fanotify_mark",
                "fchdir",
                "fchmod",
                "fchmodat",
                "fchown",
                "fchown32",
                "fchownat",
                "fcntl",
                "fcntl64",
                "fdatasync",
                "fgetxattr",
                "flistxattr",
                "flock",
                "fork",
                "fremovexattr",
                "fsetxattr",
                "fstat",
                "fstat64",
                "fstatat64",
                "fstatfs",
                "fstatfs64",
                "fsync",
                "ftruncate",
                "ftruncate64",
                "futex",
                "futimesat",
                "get_robust_list",
                "get_thread_area",
                "getcpu",
                "getcwd",
                "getdents",
                "getdents64",
                "getegid",
                "getegid32",
                "geteuid",
                "geteuid32",
                "getgid",
                "getgid32",
                "getgroups",
                "getgroups32",
                "getitimer",
                "getpeername",
                "getpgid",
                "getpgrp",
                "getpid",
                "getppid",
                "getpriority",
                "getrandom",
                "getresgid",
                "getresgid32",
                "getresuid",
                "getresuid32",
                "getrlimit",
                "getrusage",
                "getsid",
                "getsockname",
                "getsockopt",
                "gettid",
                "gettimeofday",
                "getuid",
                "getuid32",
                "getxattr",
                "inotify_add_watch",
                "inotify_init",
                "inotify_init1",
                "inotify_rm_watch",
                "io_cancel",
                "io_destroy",
                "io_getevents",
                "io_setup",
                "io_submit",
                "ioctl",
                "ioprio_get",
                "ioprio_set",
                "kill",
                "lgetxattr",
                "link",
                "linkat",
                "listen",
                "listxattr",
                "llistxattr",
                "lremovexattr",
                "lseek",
                "lsetxattr",
                "lstat",
                "lstat64",
                "madvise",
                "memfd_create",
                "mincore",
                "mkdir",
                "mkdirat",
                "mlock",
                "mlock2",
                "mlockall",
                "mmap",
                "mmap2",
                "mprotect",
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedsend",
                "mq_unlink",
                "mremap",
                "msgctl",
                "msgget",
                "msgrcv",
                "msgsnd",
                "msync",
                "munlock",
                "munlockall",
                "munmap",
                "nanosleep",
                "newfstatat",
                "open",
                "openat",
                "openat2",
                "pause",
                "pipe",
                "pipe2",
                "poll",
                "ppoll",
                "prctl",
                "pread64",
                "preadv",
                "preadv2",
                "prlimit64",
                "pselect6",
                "pwrite64",
                "pwritev",
                "pwritev2",
                "read",
                "readahead",
                "readlink",
                "readlinkat",
                "readv",
                "recv",
                "recvfrom",
                "recvmmsg",
                "recvmsg",
                "remap_file_pages",
                "removexattr",
                "rename",
                "renameat",
                "renameat2",
                "restart_syscall",
                "rmdir",
                "rt_sigaction",
                "rt_sigpending",
                "rt_sigprocmask",
                "rt_sigqueueinfo",
                "rt_sigreturn",
                "rt_sigsuspend",
                "rt_sigtimedwait",
                "rt_tgsigqueueinfo",
                "sched_get_priority_max",
                "sched_get_priority_min",
                "sched_getaffinity",
                "sched_getattr",
                "sched_getparam",
                "sched_getscheduler",
                "sched_rr_get_interval",
                "sched_setaffinity",
                "sched_setattr",
                "sched_setparam",
                "sched_setscheduler",
                "sched_yield",
                "seccomp",
                "select",
                "semctl",
                "semget",
                "semop",
                "semtimedop",
                "send",
                "sendfile",
                "sendfile64",
                "sendmmsg",
                "sendmsg",
                "sendto",
                "set_robust_list",
                "set_thread_area",
                "set_tid_address",
                "setfsgid",
                "setfsgid32",
                "setfsuid",
                "setfsuid32",
                "setgid",
                "setgid32",
                "setgroups",
                "setgroups32",
                "setitimer",
                "setpgid",
                "setpriority",
                "setregid",
                "setregid32",
                "setresgid",
                "setresgid32",
                "setresuid",
                "setresuid32",
                "setreuid",
                "setreuid32",
                "setrlimit",
                "setsid",
                "setsockopt",
                "setuid",
                "setuid32",
                "setxattr",
                "shmat",
                "shmctl",
                "shmdt",
                "shmget",
                "shutdown",
                "sigaltstack",
                "signalfd",
                "signalfd4",
                "socket",
                "socketcall",
                "socketpair",
                "splice",
                "stat",
                "stat64",
                "statfs",
                "statfs64",
                "statx",
                "symlink",
                "symlinkat",
                "sync",
                "sync_file_range",
                "syncfs",
                "tee",
                "tgkill",
                "time",
                "timer_create",
                "timer_delete",
                "timer_getoverrun",
                "timer_gettime",
                "timer_gettime64",
                "timer_settime",
                "timer_settime64",
                "timerfd_create",
                "timerfd_gettime",
                "timerfd_gettime64",
                "timerfd_settime",
                "timerfd_settime64",
                "times",
                "tkill",
                "truncate",
                "truncate64",
                "ugetrlimit",
                "umask",
                "uname",
                "unlink",
                "unlinkat",
                "unshare",
                "utime",
                "utimensat",
                "utimensat_time64",
                "utimes",
                "vfork",
                "wait4",
                "waitid",
                "waitpid",
                "write",
                "writev"
            ],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "names": [
                "clone"
            ],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {
                    "index": 0,
                    "value": 2114060288,
                    "op": "SCMP_CMP_MASKED_EQ"
                }
            ],
            "comment": "Allow clone for threads"
        }
    ]
}
EOF

# Test seccomp restrictions
cat > seccomp-test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

void test_syscall(const char* name, int result) {
    if (result == 0) {
        printf("✗ SECURITY RISK: %s succeeded\n", name);
    } else {
        printf("✓ PROTECTED: %s blocked\n", name);
    }
}

int main() {
    printf("=== Seccomp Security Test ===\n\n");
    
    // Test mount (should be blocked)
    int mount_result = mount("none", "/mnt", "tmpfs", 0, "");
    test_syscall("mount()", mount_result);
    
    // Test ptrace (should be blocked)
    int ptrace_result = ptrace(PTRACE_TRACEME, 0, 0, 0);
    test_syscall("ptrace()", ptrace_result);
    
    // Test raw socket (should be blocked)
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    test_syscall("socket(RAW)", raw_sock < 0 ? -1 : 0);
    if (raw_sock >= 0) close(raw_sock);
    
    // Test regular socket (should work)
    int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    printf("%s: Regular TCP socket\n", tcp_sock >= 0 ? "✓ ALLOWED" : "✗ BLOCKED");
    if (tcp_sock >= 0) close(tcp_sock);
    
    // Test system time change (should be blocked)
    struct timespec ts = {0, 0};
    int time_result = clock_settime(CLOCK_REALTIME, &ts);
    test_syscall("clock_settime()", time_result);
    
    return 0;
}
EOF

# Compile test program
docker run --rm -v $(pwd):/work -w /work gcc:latest gcc -o seccomp-test seccomp-test.c

# Test with and without seccomp
echo "=== Testing WITHOUT seccomp (insecure) ==="
docker run --rm --privileged --security-opt seccomp=unconfined \
    -v $(pwd)/seccomp-test:/seccomp-test alpine /seccomp-test

echo -e "\n=== Testing WITH default Docker seccomp ==="
docker run --rm -v $(pwd)/seccomp-test:/seccomp-test alpine /seccomp-test

echo -e "\n=== Testing WITH custom strict seccomp ==="
docker run --rm --security-opt seccomp=$(pwd)/webapp-seccomp.json \
    -v $(pwd)/seccomp-test:/seccomp-test alpine /seccomp-test
```

### Section 3.3: User Namespaces and Rootless Docker (60 minutes)

As of Docker 1.10, User Namespaces are supported directly by the docker daemon. This feature allows for the root user in a container to be mapped to a non uid-0 user outside the container.

### Lab 3.3: Implementing User Namespaces

**Exercise 1: