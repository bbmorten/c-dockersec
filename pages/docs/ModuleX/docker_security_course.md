# Docker Security Course - Complete Documentation

## Course Overview

This comprehensive Docker Security Course is designed to teach security professionals, developers, and system administrators how to secure Docker containers and containerized applications throughout the development lifecycle.

**Duration:** 16 hours (2 days)  
**Level:** Intermediate to Advanced  
**Prerequisites:** Basic Docker knowledge, Linux fundamentals, basic networking concepts

---

## Course Outline

### Section 1: Docker Security Fundamentals (2 hours)
- **1.1** Introduction to Container Security
- **1.2** Docker Architecture and Security Model
- **1.3** Container vs Virtual Machine Security
- **1.4** Common Docker Security Threats
- **1.5** Security by Design Principles
- **Knowledge Check Quiz 1**

### Section 2: Image Security (3 hours)
- **2.1** Secure Base Images
- **2.2** Dockerfile Security Best Practices
- **2.3** Image Vulnerability Scanning
- **2.4** Image Signing and Verification
- **2.5** Private Registry Security
- **Knowledge Check Quiz 2**

### Section 3: Runtime Security (3 hours)
- **3.1** Container Isolation and Namespaces
- **3.2** Linux Capabilities and Security
- **3.3** AppArmor and SELinux for Containers
- **3.4** Seccomp Profiles
- **3.5** Container Resource Limits
- **Knowledge Check Quiz 3**

### Section 4: Network Security (2.5 hours)
- **4.1** Docker Network Security Model
- **4.2** Network Segmentation and Isolation
- **4.3** TLS and Encryption in Transit
- **4.4** Firewall Rules and Port Management
- **4.5** Service Mesh Security
- **Knowledge Check Quiz 4**

### Section 5: Access Control and Authentication (2.5 hours)
- **5.1** Docker Daemon Security
- **5.2** User and Group Management
- **5.3** Role-Based Access Control (RBAC)
- **5.4** Secrets Management
- **5.5** Multi-factor Authentication
- **Knowledge Check Quiz 5**

### Section 6: Monitoring and Compliance (2 hours)
- **6.1** Security Monitoring and Logging
- **6.2** Runtime Threat Detection
- **6.3** Compliance Frameworks (CIS, NIST)
- **6.4** Security Auditing and Reporting
- **6.5** Incident Response
- **Knowledge Check Quiz 6**

### Section 7: Production Deployment Security (1 hour)
- **7.1** Kubernetes Security Integration
- **7.2** CI/CD Pipeline Security
- **7.3** Infrastructure as Code Security
- **7.4** Final Assessment and Best Practices Review

---

# Section 1: Docker Security Fundamentals

## Course Slides - Section 1

### Slide 1.1: Introduction to Container Security

**What is Container Security?**

Container security encompasses all the practices, tools, and technologies used to protect containerized applications and their underlying infrastructure from threats.

**Key Security Domains:**
- **Image Security** - Securing container images from build to deployment
- **Runtime Security** - Protecting running containers and their interactions
- **Host Security** - Securing the underlying infrastructure
- **Network Security** - Controlling container communications
- **Data Security** - Protecting sensitive data in containers

**Why Container Security Matters:**
- Containers share the host kernel (attack surface)
- Rapid deployment can bypass traditional security controls
- Microservices increase attack vectors
- Container images may contain vulnerabilities
- Orchestration complexity introduces new risks

### Slide 1.2: Docker Architecture and Security Model

**Docker Architecture Components:**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Docker CLI    │    │  Docker Images  │    │   Registries    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
┌─────────────────────────────────────────────────────────────────┐
│                     Docker Daemon                              │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   Container     │    Network      │      Volume               │
│   Management    │   Management    │    Management             │
└─────────────────┴─────────────────┴─────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                     Host Operating System                      │
└─────────────────────────────────────────────────────────────────┘
```

**Security Boundaries:**
- **Container Isolation** - Process and filesystem isolation using namespaces
- **Resource Control** - CPU, memory, and I/O limits using cgroups
- **Capability Dropping** - Removing unnecessary Linux capabilities
- **Read-only Root Filesystem** - Preventing runtime modifications

### Slide 1.3: Container vs Virtual Machine Security

**Security Comparison:**

| Aspect | Virtual Machines | Containers |
|--------|------------------|------------|
| **Isolation Level** | Hardware virtualization | Process-level isolation |
| **Kernel Sharing** | Separate guest kernels | Shared host kernel |
| **Attack Surface** | Hypervisor vulnerabilities | Kernel vulnerabilities |
| **Resource Overhead** | High (full OS) | Low (shared kernel) |
| **Boot Time** | Minutes | Seconds |
| **Security Maturity** | Well-established | Rapidly evolving |

**Container Security Challenges:**
- **Shared Kernel Risk** - Container escape to host
- **Privilege Escalation** - Gaining elevated permissions
- **Resource Exhaustion** - DoS through resource consumption
- **Image Vulnerabilities** - Vulnerable packages in base images

### Slide 1.4: Common Docker Security Threats

**OWASP Top 10 Container Security Risks:**

1. **Insecure Container Images**
   - Vulnerable base images
   - Embedded secrets
   - Excessive privileges

2. **Compromised Credentials**
   - Hardcoded passwords
   - Weak authentication
   - Credential leakage

3. **Overly Permissive Access**
   - Running as root
   - Excessive capabilities
   - Privileged containers

4. **Container Escape**
   - Kernel exploits
   - Misconfigured security policies
   - Privilege escalation

5. **Network Misconfigurations**
   - Exposed ports
   - Lack of network segmentation
   - Unencrypted communications

### Slide 1.5: Security by Design Principles

**Fundamental Security Principles:**

**1. Principle of Least Privilege**
- Grant minimum necessary permissions
- Use non-root users when possible
- Drop unnecessary Linux capabilities
- Apply resource limits

**2. Defense in Depth**
- Multiple security layers
- Network segmentation
- Runtime protection
- Monitoring and alerting

**3. Fail Securely**
- Secure defaults
- Graceful degradation
- Error handling without information disclosure

**4. Keep Security Simple**
- Minimize attack surface
- Use well-tested components
- Clear security policies
- Regular security reviews

---

## Graphics for Section 1

### Graphic 1.1: Container Security Layers

```
     ┌─────────────────────────────────────────┐
     │            APPLICATION LAYER            │
     │        (Application Security)           │
     ├─────────────────────────────────────────┤
     │            CONTAINER LAYER              │
     │     (Runtime & Image Security)          │
     ├─────────────────────────────────────────┤
     │           ORCHESTRATION LAYER           │
     │      (Kubernetes/Docker Swarm)          │
     ├─────────────────────────────────────────┤
     │              HOST LAYER                 │
     │        (OS & Kernel Security)           │
     ├─────────────────────────────────────────┤
     │           INFRASTRUCTURE LAYER          │
     │       (Network & Hardware Security)     │
     └─────────────────────────────────────────┘
```

### Graphic 1.2: Docker Security Attack Surface

```
    External Threats                 Internal Threats
         │                                │
         ▼                                ▼
    ┌─────────┐                     ┌─────────┐
    │Registry │                     │ Insider │
    │Attacks  │                     │ Threats │
    └─────────┘                     └─────────┘
         │                                │
         ▼                                ▼
    ╔═══════════════════════════════════════════╗
    ║              DOCKER HOST                  ║
    ╠═══════════════════════════════════════════╣
    ║  ┌─────────┐  ┌─────────┐  ┌─────────┐   ║
    ║  │Container│  │Container│  │Container│   ║
    ║  │    A    │  │    B    │  │    C    │   ║
    ║  └─────────┘  └─────────┘  └─────────┘   ║
    ║              Docker Daemon                ║
    ║           Host Operating System           ║
    ╚═══════════════════════════════════════════╝
```

---

## Hands-on Lab Exercises - Section 1

### Lab 1.1: Docker Security Assessment

**Objective:** Assess the current security posture of a Docker installation

**Prerequisites:**
- Docker Desktop installed on Windows or Ubuntu
- Administrative/sudo access

#### For Windows (Docker Desktop):

**Step 1: Verify Docker Installation Security**
```powershell
# Check Docker version and security features
docker version
docker info

# Verify Docker daemon is running with proper permissions
Get-Service docker
```

**Step 2: Analyze Container Runtime Security**
```powershell
# Run a container and check its security context
docker run -it --rm ubuntu:latest bash

# Inside the container, check user permissions
whoami
id
cat /proc/self/status | grep Cap
```

#### For Ubuntu (Docker Desktop):

**Step 1: Verify Docker Installation Security**
```bash
# Check Docker version and security features
docker version
docker info

# Verify Docker daemon is running with proper permissions
sudo systemctl status docker
```

**Step 2: Analyze Container Runtime Security**
```bash
# Run a container and check its security context
docker run -it --rm ubuntu:latest bash

# Inside the container, check user permissions
whoami
id
cat /proc/self/status | grep Cap
cat /proc/self/uid_map
cat /proc/self/gid_map
```

**Step 3: Security Scanning with Docker Scout**
```bash
# Enable Docker Scout (if available)
docker scout quickview

# Scan an image for vulnerabilities
docker scout cves ubuntu:latest
```

### Lab 1.2: Container Escape Demonstration

**Objective:** Understand container escape risks (Educational purposes only)

**Warning:** Perform only in isolated test environments

```bash
# Example of privileged container risk
docker run -it --privileged ubuntu:latest bash

# Inside the privileged container
ls /dev
mount /dev/sda1 /mnt
ls /mnt  # Host filesystem access

# Exit and remove container
exit
docker container prune -f
```

---

## Knowledge Check Quiz - Section 1

### Question 1 (Multiple Choice)
What is the primary security difference between containers and virtual machines?

A) Containers provide better isolation than VMs
B) VMs share the host kernel while containers don't
C) Containers share the host kernel while VMs have separate kernels
D) There is no significant security difference

**Answer: C**

### Question 2 (True/False)
Running containers as root user is acceptable if proper network isolation is implemented.

**Answer: False** - Containers should run as non-root users regardless of network isolation.

### Question 3 (Multiple Choice)
Which of the following is NOT a layer in the container security model?

A) Application Layer
B) Container Layer
C) Database Layer
D) Host Layer

**Answer: C**

### Question 4 (Short Answer)
List three key principles of "Security by Design" for containers.

**Answer:**
1. Principle of Least Privilege
2. Defense in Depth
3. Fail Securely / Keep Security Simple

### Question 5 (Multiple Choice)
What is the most effective way to reduce container attack surface?

A) Use the latest base images only
B) Minimize installed packages and run as non-root
C) Increase resource limits
D) Use multiple network interfaces

**Answer: B**

---

# Section 2: Image Security

## Course Slides - Section 2

### Slide 2.1: Secure Base Images

**Choosing Secure Base Images:**

**Minimal Base Images:**
- **Distroless Images** - Google's distroless images contain only application and runtime dependencies
- **Alpine Linux** - Security-oriented, minimal Linux distribution
- **Scratch** - Empty base image for static binaries

**Image Selection Criteria:**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Official      │    │   Minimal       │    │   Updated       │
│   Repositories  │    │   Attack        │    │   Regularly     │
│                 │    │   Surface       │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Secure Base   │
                    │     Image       │
                    └─────────────────┘
```

**Base Image Security Comparison:**

| Image Type | Size | Vulnerabilities | Use Case |
|------------|------|-----------------|----------|
| `ubuntu:latest` | 72MB | High | Development |
| `alpine:latest` | 5MB | Low | Production |
| `distroless/java` | 120MB | Minimal | Java apps |
| `scratch` | 0MB | None | Static binaries |

### Slide 2.2: Dockerfile Security Best Practices

**Secure Dockerfile Structure:**

```dockerfile
# Use specific version tags, not 'latest'
FROM alpine:3.18

# Create non-root user early
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Install only required packages
RUN apk add --no-cache \
    ca-certificates \
    tzdata

# Copy application files with proper ownership
COPY --chown=appuser:appgroup app /app/

# Use non-root user
USER appuser

# Set secure working directory
WORKDIR /app

# Expose only required ports
EXPOSE 8080

# Use exec form for better signal handling
CMD ["./app"]
```

**Security Anti-patterns to Avoid:**

❌ **DON'T:**
```dockerfile
FROM ubuntu:latest                    # Avoid 'latest' tags
RUN apt-get update                   # Missing && apt-get install
ADD https://example.com/file.tar.gz  # Use COPY instead
USER root                           # Avoid root user
RUN chmod 777 /app                  # Excessive permissions
```

✅ **DO:**
```dockerfile
FROM ubuntu:20.04                    # Use specific versions
RUN apt-get update && apt-get install # Chain commands
COPY file.tar.gz /tmp/              # Use COPY for local files
USER 1001                           # Use non-root user
RUN chmod 755 /app                  # Minimal permissions
```

### Slide 2.3: Image Vulnerability Scanning

**Vulnerability Scanning Pipeline:**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Build     │───▶│   Scan      │───▶│   Report    │───▶│   Deploy    │
│   Image     │    │   Image     │    │ Findings    │    │   or Block  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

**Popular Vulnerability Scanners:**

1. **Docker Scout** (Built-in)
   ```bash
   docker scout cves <image>
   docker scout recommendations <image>
   ```

2. **Trivy** (Aqua Security)
   ```bash
   trivy image <image>
   trivy fs <dockerfile-directory>
   ```

3. **Clair** (Red Hat)
   - API-driven vulnerability scanner
   - Continuous monitoring

4. **Snyk** (Commercial)
   - Developer-focused scanning
   - IDE integration

**Vulnerability Severity Levels:**
- **Critical** - Immediate action required
- **High** - Address within 24 hours
- **Medium** - Address within 1 week
- **Low** - Address during next maintenance window

### Slide 2.4: Image Signing and Verification

**Docker Content Trust (DCT):**

Docker Content Trust provides cryptographic signing and verification of image tags.

**Enabling DCT:**
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest  # Will verify signature
```

**Signing Process:**
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Developer │───▶│   Sign      │───▶│   Registry  │
│   Build     │    │   Image     │    │   Store     │
└─────────────┘    └─────────────┘    └─────────────┘
                           │
                           ▼
                  ┌─────────────┐
                  │   Notary    │
                  │   Server    │
                  └─────────────┘
```

**Cosign (Sigstore):**
Modern container signing with transparency logs:

```bash
# Sign an image
cosign sign <image>

# Verify signature
cosign verify <image> --key cosign.pub
```

### Slide 2.5: Private Registry Security

**Private Registry Security Controls:**

**Authentication & Authorization:**
- RBAC (Role-Based Access Control)
- LDAP/Active Directory integration
- API token management
- Multi-factor authentication

**Registry Security Architecture:**
```
┌─────────────────────────────────────────────────────┐
│                 Private Registry                    │
├─────────────────┬─────────────────┬─────────────────┤
│   Auth Layer    │   Storage       │    Scanning     │
│   (RBAC/LDAP)   │   (Encrypted)   │   (Automated)   │
└─────────────────┴─────────────────┴─────────────────┘
         │                  │                  │
         ▼                  ▼                  ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Users/    │    │  Registry   │    │ Vulnerability│
│   Groups    │    │  Storage    │    │  Database   │
└─────────────┘    └─────────────┘    └─────────────┘
```

**Registry Hardening Checklist:**
- ✅ TLS encryption for all communications
- ✅ Regular security updates
- ✅ Access logging and monitoring
- ✅ Image scanning automation
- ✅ Backup and disaster recovery
- ✅ Network isolation

---

## Hands-on Lab Exercises - Section 2

### Lab 2.1: Secure Dockerfile Creation

**Objective:** Create a secure Dockerfile for a simple web application

#### For Both Windows and Ubuntu:

**Step 1: Create a Secure Dockerfile**
```dockerfile
# Create a file named 'Dockerfile.secure'
FROM alpine:3.18

# Update packages and install required tools
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Create app directory
RUN mkdir /app && chown appuser:appgroup /app

# Copy application files
COPY --chown=appuser:appgroup app.py /app/
COPY --chown=appuser:appgroup requirements.txt /app/

# Switch to non-root user
USER appuser

# Set working directory
WORKDIR /app

# Install Python dependencies
RUN pip3 install --user --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 8080

# Set health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Use exec form for proper signal handling
CMD ["python3", "app.py"]
```

**Step 2: Create Sample Application Files**

Create `app.py`:
```python
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'status': 'healthy', 'service': 'secure-app'}
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), HealthHandler)
    print('Starting server on port 8080...')
    server.serve_forever()
```

Create `requirements.txt`:
```
# No external dependencies for this simple example
```

**Step 3: Build and Test the Secure Image**
```bash
# Build the secure image
docker build -f Dockerfile.secure -t secure-app:1.0 .

# Inspect the image
docker inspect secure-app:1.0

# Run the container
docker run -d --name secure-app -p 8080:8080 secure-app:1.0

# Test the application
curl http://localhost:8080/health

# Check container user
docker exec secure-app whoami
docker exec secure-app id

# Cleanup
docker stop secure-app
docker rm secure-app
```

### Lab 2.2: Image Vulnerability Scanning

**Objective:** Scan container images for vulnerabilities using multiple tools

#### For Windows (PowerShell):

**Step 1: Docker Scout Scanning**
```powershell
# Scan a vulnerable image
docker scout cves node:16

# Get recommendations
docker scout recommendations node:16

# Compare with a newer version
docker scout compare --to node:18 node:16
```

**Step 2: Install and Use Trivy**
```powershell
# Install Trivy using Chocolatey (if available)
# choco install trivy

# Or download binary from GitHub releases
# https://github.com/aquasecurity/trivy/releases

# Scan image with Trivy
trivy image node:16

# Scan with specific severity
trivy image --severity HIGH,CRITICAL node:16

# Generate JSON report
trivy image --format json --output report.json node:16
```

#### For Ubuntu:

**Step 1: Docker Scout Scanning**
```bash
# Scan a vulnerable image
docker scout cves node:16

# Get recommendations
docker scout recommendations node:16

# Compare with a newer version
docker scout compare --to node:18 node:16
```

**Step 2: Install and Use Trivy**
```bash
# Install Trivy
sudo apt-get update
sudo apt-get install wget apt-transport-https gnupg lsb-release

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list

sudo apt-get update
sudo apt-get install trivy

# Scan image with Trivy
trivy image node:16

# Scan with specific severity
trivy image --severity HIGH,CRITICAL node:16

# Generate JSON report
trivy image --format json --output report.json node:16

# Scan filesystem
trivy fs .
```

### Lab 2.3: Image Signing with Cosign

**Objective:** Sign and verify container images using Cosign

#### For Both Windows and Ubuntu:

**Step 1: Install Cosign**
```bash
# Download and install Cosign
# Visit: https://github.com/sigstore/cosign/releases
# Follow installation instructions for your platform
```

**Step 2: Generate Key Pair**
```bash
# Generate key pair for signing
cosign generate-key-pair

# This creates cosign.key and cosign.pub files
```

**Step 3: Sign an Image**
```bash
# Build a test image
docker build -t test-app:signed .

# Tag for local registry
docker tag test-app:signed localhost:5000/test-app:signed

# Run local registry (for testing)
docker run -d -p 5000:5000 --name registry registry:2

# Push to local registry
docker push localhost:5000/test-app:signed

# Sign the image
cosign sign --key cosign.key localhost:5000/test-app:signed
```

**Step 4: Verify Signature**
```bash
# Verify the signature
cosign verify --key cosign.pub localhost:5000/test-app:signed

# Cleanup
docker stop registry
docker rm registry
```

---

## Knowledge Check Quiz - Section 2

### Question 1 (Multiple Choice)
Which base image provides the smallest attack surface?

A) ubuntu:latest
B) alpine:latest
C) distroless/java
D) scratch

**Answer: D**

### Question 2 (True/False)
It's acceptable to use the 'latest' tag in production Dockerfiles.

**Answer: False** - Always use specific version tags for reproducibility and security.

### Question 3 (Multiple Choice)
What is the primary purpose of Docker Content Trust?

A) Compress images
B) Speed up builds
C) Cryptographically sign and verify images
D) Reduce image size

**Answer: C**

### Question 4 (Multiple Choice)
Which Dockerfile instruction should be avoided for security reasons?

A) USER 1001
B) ADD https://example.com/file.tar
C) COPY --chown=user:group file /app/
D) EXPOSE 8080

**Answer: B** - ADD from URLs can introduce security risks; use COPY for local files.

### Question 5 (Short Answer)
Name three security benefits of using minimal base images like Alpine or distroless.

**Answer:**
1. Reduced attack surface (fewer packages)
2. Lower vulnerability count
3. Smaller image size (faster deployment)

---

# Section 3: Runtime Security

## Course Slides - Section 3

### Slide 3.1: Container Isolation and Namespaces

**Linux Namespaces for Container Isolation:**

Namespaces provide process-level isolation by creating separate instances of global system resources.

**Key Namespace Types:**

| Namespace | Purpose | Isolation Provided |
|-----------|---------|-------------------|
| **PID** | Process IDs | Process visibility and numbering |
| **NET** | Network | Network interfaces, routing, ports |
| **MNT** | Mount points | Filesystem mount points |
| **UTS** | Hostname | System hostname and domain |
| **IPC** | Inter-process | Message queues, semaphores |
| **USER** | User/Group IDs | User and group ID mappings |

**Namespace Visualization:**
```
Host System
├── PID Namespace 1 (Container A)
│   ├── Process 1 (init)
│   ├── Process 2 (app)
│   └── Process 3 (helper)
├── PID Namespace 2 (Container B)
│   ├── Process 1 (init)
│   └── Process 2 (service)
└── Host PID Namespace
    ├── Process 1 (systemd)
    ├── Process 1234 (dockerd)
    └── Process 5678 (container runtime)
```

**Security Benefits:**
- Process isolation prevents cross-container interference
- Network isolation controls container communications
- Filesystem isolation protects host and other containers
- User namespace mapping reduces privilege escalation risks

### Slide 3.2: Linux Capabilities and Security

**Linux Capabilities System:**

Capabilities divide root privileges into discrete units that can be independently enabled or disabled.

**Default Docker Capabilities:**
```
Capability          Description                    Security Risk
CAP_CHOWN          Change file ownership          Medium
CAP_DAC_OVERRIDE   Bypass file permissions        High
CAP_FOWNER         Bypass ownership checks        Medium
CAP_FSETID         Set file UID/GID               Medium
CAP_KILL           Send signals to processes      Low
CAP_SETGID         Change group ID                Medium
CAP_SETUID         Change user ID                 High
CAP_NET_BIND_SERVICE  Bind to privileged ports    Low
CAP_SYS_CHROOT     Use chroot()                   Medium
```

**Capability Management:**
```bash
# Drop all capabilities
docker run --cap-drop=ALL ubuntu

# Add specific capability
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx

# List container capabilities
docker exec <container> capsh --print
```

**Security Best Practices:**
- Drop all capabilities by default: `--cap-drop=ALL`
- Add only required capabilities: `--cap-add=<specific>`
- Never grant `CAP_SYS_ADMIN` unless absolutely necessary
- Use `--read-only` filesystem when possible

### Slide 3.3: AppArmor and SELinux for Containers

**Mandatory Access Control (MAC) Systems:**

**AppArmor (Application Armor):**
- Path-based access control
- Simpler policy syntax
- Default on Ubuntu

**SELinux (Security-Enhanced Linux):**
- Label-based access control
- More granular controls
- Default on RHEL/CentOS

**AppArmor Profile Example:**
```bash
# Check if AppArmor is enabled
sudo aa-status

# Docker's default AppArmor profile location
/etc/apparmor.d/docker

# Run container with custom AppArmor profile
docker run --security-opt apparmor=my-profile ubuntu
```

**SELinux Context Example:**
```bash
# Check SELinux status
sestatus

# Run container with SELinux context
docker run --security-opt label=level:s0:c100,c200 ubuntu

# View container SELinux labels
ps -eZ | grep docker
```

**MAC Security Benefits:**
- Prevents privilege escalation attacks
- Limits filesystem access
- Controls network communications
- Provides audit logging

### Slide 3.4: Seccomp Profiles

**Secure Computing (seccomp) Mode:**

Seccomp restricts system calls available to containers, reducing the kernel attack surface.

**Seccomp Modes:**
1. **Strict Mode** - Only read, write, exit, sigreturn allowed
2. **Filter Mode** - Custom whitelist/blacklist of system calls

**Docker's Default Seccomp Profile:**
- Blocks ~300 out of ~400 system calls
- Allows safe operations (file I/O, networking)
- Blocks dangerous calls (mount, reboot, kernel modules)

**Custom Seccomp Profile Example:**
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "exit", "exit_group"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["open", "openat", "close"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["brk", "mmap", "munmap"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Using Custom Seccomp:**
```bash
# Run with custom seccomp profile
docker run --security-opt seccomp=my-profile.json ubuntu

# Disable seccomp (not recommended)
docker run --security-opt seccomp=unconfined ubuntu

# Check blocked system calls
docker run ubuntu strace -c ls 2>&1 | grep EPERM
```

### Slide 3.5: Container Resource Limits

**Resource Control with cgroups:**

Control Groups (cgroups) limit and monitor container resource usage.

**Resource Types:**
- **CPU** - Processing power allocation
- **Memory** - RAM usage limits
- **Disk I/O** - Storage bandwidth
- **Network** - Bandwidth allocation
- **PIDs** - Process count limits

**Resource Limit Examples:**
```bash
# Memory limits
docker run -m 512m ubuntu                    # 512MB RAM limit
docker run --oom-kill-disable -m 512m ubuntu # Disable OOM killer

# CPU limits
docker run --cpus="1.5" ubuntu              # 1.5 CPU cores
docker run --cpu-shares=512 ubuntu          # Relative CPU weight

# Disk I/O limits
docker run --device-read-bps /dev/sda:1mb ubuntu    # 1MB/s read
docker run --device-write-bps /dev/sda:1mb ubuntu   # 1MB/s write

# Process limits
docker run --pids-limit 100 ubuntu          # Max 100 processes

# Combined limits
docker run \
  -m 1g \
  --cpus="2" \
  --pids-limit 1000 \
  ubuntu
```

**Resource Monitoring:**
```bash
# Monitor resource usage
docker stats

# Get detailed container metrics
docker exec <container> cat /proc/meminfo
docker exec <container> cat /proc/cpuinfo
```

---

## Hands-on Lab Exercises - Section 3

### Lab 3.1: Namespace Isolation Testing

**Objective:** Understand container isolation through namespaces

#### For Both Windows and Ubuntu:

**Step 1: Process Namespace Isolation**
```bash
# Run container and check process visibility
docker run -it --name ns-test ubuntu bash

# Inside container - check processes
ps aux
# Should only see container processes, not host processes

# Check PID namespace
ls -la /proc/self/ns/

# Exit container
exit
```

**Step 2: Network Namespace Isolation**
```bash
# Run container with custom network
docker network create --driver bridge isolated-net

docker run -it --network isolated-net --name net-test ubuntu bash

# Inside container - check network interfaces
ip addr show
ip route show

# Try to access host services
ping host.docker.internal  # May fail depending on configuration

# Exit and cleanup
exit
docker rm net-test
docker network rm isolated-net
```

**Step 3: User Namespace Mapping**
```bash
# Run container and check user mapping
docker run -it --user 1000:1000 ubuntu bash

# Inside container
whoami
id
cat /proc/self/uid_map
cat /proc/self/gid_map

# Exit container
exit
```

### Lab 3.2: Linux Capabilities Management

**Objective:** Practice dropping and adding capabilities for security

#### For Both Windows and Ubuntu:

**Step 1: Default Capabilities Assessment**
```bash
# Run container with default capabilities
docker run -it --name cap-test ubuntu bash

# Inside container - check capabilities
apt-get update && apt-get install -y libcap2-bin
capsh --print

# Try privilege operations
chown root:root /tmp  # Should work with CAP_CHOWN

# Exit container
exit
docker rm cap-test
```

**Step 2: Drop All Capabilities**
```bash
# Run container with no capabilities
docker run -it --cap-drop=ALL --name no-caps ubuntu bash

# Inside container
apt-get update && apt-get install -y libcap2-bin
capsh --print

# Try same operations - should fail
chown root:root /tmp  # Should fail

# Exit container
exit
docker rm no-caps
```

**Step 3: Selective Capability Addition**
```bash
# Run with specific capabilities only
docker run -it \
  --cap-drop=ALL \
  --cap-add=CHOWN \
  --cap-add=DAC_OVERRIDE \
  --name selective-caps ubuntu bash

# Inside container
apt-get update && apt-get install -y libcap2-bin
capsh --print

# Test specific operations
chown root:root /tmp  # Should work
mkdir /restricted && chmod 000 /restricted
touch /restricted/test  # Should work with DAC_OVERRIDE

# Exit container
exit
docker rm selective-caps
```

### Lab 3.3: Seccomp Profile Testing

**Objective:** Create and test custom seccomp profiles

#### For Both Windows and Ubuntu:

**Step 1: Create Custom Seccomp Profile**

Create `restricted-profile.json`:
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ],
  "syscalls": [
    {
      "names": [
        "read",
        "write",
        "exit",
        "exit_group",
        "open",
        "openat",
        "close",
        "stat",
        "fstat",
        "lstat",
        "brk",
        "mmap",
        "munmap",
        "access",
        "execve",
        "getpid",
        "getuid",
        "getgid"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Step 2: Test Default Seccomp**
```bash
# Run with default seccomp
docker run -it ubuntu bash

# Inside container - try restricted operations
mount  # Should be blocked
reboot  # Should be blocked

# Exit container
exit
```

**Step 3: Test Custom Seccomp Profile**
```bash
# Run with custom seccomp profile
docker run -it --security-opt seccomp=restricted-profile.json ubuntu bash

# Inside container - try basic operations
ls /  # Should work
echo "test"  # Should work
ps  # May fail due to restricted syscalls

# Exit container
exit
```

**Step 4: Disable Seccomp (Testing Only)**
```bash
# Run without seccomp (not recommended for production)
docker run -it --security-opt seccomp=unconfined ubuntu bash

# Inside container - more operations should be available
mount  # May still fail due to other restrictions
uname -a  # Should work

# Exit container
exit
```

### Lab 3.4: Resource Limits Implementation

**Objective:** Implement and test container resource limits

#### For Both Windows and Ubuntu:

**Step 1: Memory Limits**
```bash
# Create memory stress test
docker run -it --memory=100m --name memory-test ubuntu bash

# Inside container
apt-get update && apt-get install -y stress

# Test memory limit
stress --vm 1 --vm-bytes 150M --timeout 10s
# Should be killed by OOM killer

# Exit container
exit
docker rm memory-test
```

**Step 2: CPU Limits**
```bash
# Create CPU stress test
docker run -it --cpus="0.5" --name cpu-test ubuntu bash

# Inside container
apt-get update && apt-get install -y stress

# Test CPU limit
stress --cpu 2 --timeout 10s

# Monitor from host (in another terminal)
docker stats cpu-test

# Exit container
exit
docker rm cpu-test
```

**Step 3: Combined Resource Limits**
```bash
# Run with multiple resource constraints
docker run -d \
  --name resource-limited \
  --memory=512m \
  --cpus="1.0" \
  --pids-limit=100 \
  --restart=unless-stopped \
  nginx:alpine

# Monitor resource usage
docker stats resource-limited

# Check container limits
docker inspect resource-limited | grep -A 10 "Resources"

# Cleanup
docker stop resource-limited
docker rm resource-limited
```

---

## Knowledge Check Quiz - Section 3

### Question 1 (Multiple Choice)
Which Linux namespace provides network isolation for containers?

A) PID namespace
B) NET namespace
C) MNT namespace
D) IPC namespace

**Answer: B**

### Question 2 (True/False)
It's safe to run containers with --cap-add=SYS_ADMIN in production.

**Answer: False** - SYS_ADMIN provides extensive privileges and should be avoided.

### Question 3 (Multiple Choice)
What is the primary purpose of seccomp in container security?

A) Limit memory usage
B) Control network access
C) Restrict available system calls
D) Manage file permissions

**Answer: C**

### Question 4 (Multiple Choice)
Which command drops all Linux capabilities from a container?

A) docker run --no-caps ubuntu
B) docker run --cap-drop=ALL ubuntu
C) docker run --secure ubuntu
D) docker run --capabilities=none ubuntu

**Answer: B**

### Question 5 (Short Answer)
Name three types of resources that can be limited using cgroups in Docker containers.

**Answer:**
1. Memory (RAM usage)
2. CPU (processing power)
3. Disk I/O (storage bandwidth)

---

# Section 4: Network Security

## Course Slides - Section 4

### Slide 4.1: Docker Network Security Model

**Docker Network Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│                    Host Network                         │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Bridge    │  │   Overlay   │  │    Host     │     │
│  │   Network   │  │   Network   │  │   Network   │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│         │                │                │            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ Container A │  │ Container B │  │ Container C │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
```

**Network Driver Types:**

| Driver | Use Case | Security Level | Isolation |
|--------|----------|----------------|-----------|
| **bridge** | Single host | Medium | Container-to-container |
| **host** | Performance | Low | No network isolation |
| **overlay** | Multi-host | High | Encrypted by default |
| **macvlan** | Legacy apps | Medium | VLAN-based |
| **none** | Maximum security | Highest | Complete isolation |

**Default Security Features:**
- Container-to-container isolation on different networks
- Automatic IP address management
- Built-in DNS resolution
- Port publishing controls

### Slide 4.2: Network Segmentation and Isolation

**Network Segmentation Strategy:**

```
Production Environment Network Segmentation

┌─────────────────────────────────────────────────────────┐
│                  DMZ Network                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │  Load       │  │   Web       │  │   Proxy     │     │
│  │ Balancer    │  │  Server     │  │  Server     │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                Application Network                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │    API      │  │  Business   │  │   Cache     │     │
│  │  Gateway    │  │   Logic     │  │  Service    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────┐
│                 Database Network                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │  Primary    │  │   Replica   │  │   Backup    │     │
│  │  Database   │  │  Database   │  │  Service    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
```

**Network Isolation Commands:**
```bash
# Create isolated networks
docker network create --driver bridge frontend-net
docker network create --driver bridge backend-net
docker network create --driver bridge database-net

# Run containers in specific networks
docker run -d --network frontend-net nginx:alpine
docker run -d --network backend-net node:alpine
docker run -d --network database-net postgres:alpine

# Connect container to multiple networks
docker network connect backend-net frontend-container
```

**Security Benefits:**
- Prevent lateral movement between tiers
- Limit blast radius of compromises
- Implement principle of least privilege
- Enable network monitoring and logging

### Slide 4.3: TLS and Encryption in Transit

**Container Communication Encryption:**

**TLS Termination Strategies:**

1. **Edge Termination** - TLS terminated at load balancer
2. **Passthrough** - TLS terminated at application
3. **Re-encryption** - TLS terminated and re-encrypted

**Mutual TLS (mTLS) for Container-to-Container:**

```
┌─────────────┐    Encrypted     ┌─────────────┐
│  Service A  │ ◄─────────────► │  Service B  │
│             │   Channel       │             │
│ Client Cert │                 │Server Cert  │
└─────────────┘                 └─────────────┘
        │                               │
        ▼                               ▼
┌─────────────┐                 ┌─────────────┐
│     CA      │                 │     CA      │
│Certificate  │                 │Certificate  │
└─────────────┘                 └─────────────┘
```

**Docker TLS Configuration:**
```bash
# Generate certificates for Docker daemon
openssl genrsa -aes256 -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

# Configure Docker daemon with TLS
dockerd \
  --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=server-cert.pem \
  --tlskey=server-key.pem \
  -H=0.0.0.0:2376

# Client connection with TLS
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=cert.pem \
  --tlskey=key.pem \
  -H=$HOST:2376 version
```

### Slide 4.4: Firewall Rules and Port Management

**Container Port Security:**

**Port Publishing Security Model:**
```
Host Firewall Rules
├── ACCEPT: 22/tcp (SSH - Admin only)
├── ACCEPT: 80/tcp (HTTP - Public)
├── ACCEPT: 443/tcp (HTTPS - Public)
├── DROP: 2376/tcp (Docker API - Internal only)
└── DROP: ALL (Default deny)

Container Port Mapping
├── 80:8080 (Nginx container)
├── 443:8443 (Nginx container)
└── 3306:3306 (MySQL - Internal network only)
```

**Secure Port Publishing:**
```bash
# Bind to specific interface only
docker run -p 127.0.0.1:3306:3306 mysql

# Use custom networks instead of port publishing
docker network create app-network
docker run --network app-network mysql

# Restrict to specific IP ranges with iptables
iptables -A DOCKER-USER -s 192.168.1.0/24 -j ACCEPT
iptables -A DOCKER-USER -j DROP
```

**Firewall Configuration Best Practices:**
- Use specific interface binding (127.0.0.1, internal IPs)
- Implement default deny policies
- Regular firewall rule audits
- Network monitoring and alerting
- Integration with container orchestration

### Slide 4.5: Service Mesh Security

**Service Mesh Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│                 Service Mesh Layer                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Proxy     │  │   Proxy     │  │   Proxy     │     │
│  │  (Envoy)    │  │  (Envoy)    │  │  (Envoy)    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
└─────────────────────────────────────────────────────────┘
         │                 │                 │
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Service A  │   │  Service B  │   │  Service C  │
└─────────────┘   └─────────────┘   └─────────────┘
```

**Security Features:**
- **Automatic mTLS** - Encrypted service-to-service communication
- **Identity-based Access Control** - Fine-grained authorization
- **Traffic Management** - Circuit breaking, rate limiting
- **Security Policies** - Centralized policy enforcement
- **Observability** - Detailed traffic monitoring

**Popular Service Mesh Solutions:**

| Solution | Strengths | Container Support |
|----------|-----------|------------------|
| **Istio** | Feature-rich, mature | Kubernetes native |
| **Linkerd** | Lightweight, simple | Kubernetes focus |
| **Consul Connect** | HashiCorp ecosystem | Multi-platform |
| **AWS App Mesh** | AWS integration | ECS/EKS support |

---

## Hands-on Lab Exercises - Section 4

### Lab 4.1: Network Segmentation Implementation

**Objective:** Create network segmentation for a multi-tier application

#### For Both Windows and Ubuntu:

**Step 1: Create Network Segments**
```bash
# Create three network tiers
docker network create \
  --driver bridge \
  --subnet=172.20.1.0/24 \
  frontend-tier

docker network create \
  --driver bridge \
  --subnet=172.20.2.0/24 \
  --internal \
  backend-tier

docker network create \
  --driver bridge \
  --subnet=172.20.3.0/24 \
  --internal \
  database-tier

# Verify networks
docker network ls
docker network inspect frontend-tier
```

**Step 2: Deploy Multi-tier Application**
```bash
# Deploy database (most restricted)
docker run -d \
  --name database \
  --network database-tier \
  -e POSTGRES_PASSWORD=secret \
  postgres:alpine

# Deploy backend API (middle tier)
docker run -d \
  --name api-server \
  --network backend-tier \
  node:alpine sleep 3600

# Connect backend to database network
docker network connect database-tier api-server

# Deploy frontend (public tier)
docker run -d \
  --name web-server \
  --network frontend-tier \
  -p 8080:80 \
  nginx:alpine

# Connect frontend to backend network
docker network connect backend-tier web-server
```

**Step 3: Test Network Isolation**
```bash
# Test frontend can reach backend
docker exec web-server ping -c 3 api-server

# Test backend can reach database
docker exec api-server ping -c 3 database

# Test frontend cannot directly reach database (should fail)
docker exec web-server ping -c 3 database
```

**Step 4: Cleanup**
```bash
# Remove containers
docker stop database api-server web-server
docker rm database api-server web-server

# Remove networks
docker network rm frontend-tier backend-tier database-tier
```

### Lab 4.2: TLS Configuration for Containers

**Objective:** Configure TLS encryption for container communications

#### For Both Windows and Ubuntu:

**Step 1: Generate TLS Certificates**
```bash
# Create certificate directory
mkdir -p tls-lab/certs
cd tls-lab

# Generate CA private key
openssl genrsa -out certs/ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key certs/ca-key.pem \
  -sha256 -out certs/ca.pem \
  -subj "/C=US/ST=CA/L=SF/O=Docker/CN=ca"

# Generate server private key
openssl genrsa -out certs/server-key.pem 4096

# Generate server certificate signing request
openssl req -subj "/C=US/ST=CA/L=SF/O=Docker/CN=server" \
  -sha256 -new -key certs/server-key.pem \
  -out certs/server.csr

# Create certificate extensions
echo "subjectAltName = DNS:localhost,IP:127.0.0.1" > certs/extfile.cnf
echo "extendedKeyUsage = serverAuth" >> certs/extfile.cnf

# Generate server certificate
openssl x509 -req -days 365 -sha256 \
  -in certs/server.csr \
  -CA certs/ca.pem \
  -CAkey certs/ca-key.pem \
  -out certs/server-cert.pem \
  -extfile certs/extfile.cnf \
  -CAcreateserial
```

**Step 2: Configure NGINX with TLS**

Create `nginx-tls.conf`:
```nginx
server {
    listen 443 ssl;
    server_name localhost;
    
    ssl_certificate /etc/nginx/certs/server-cert.pem;
    ssl_certificate_key /etc/nginx/certs/server-key.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    location / {
        return 200 "Secure connection established\n";
        add_header Content-Type text/plain;
    }
}
```

**Step 3: Run TLS-enabled Container**
```bash
# Run NGINX with TLS configuration
docker run -d \
  --name nginx-tls \
  -p 8443:443 \
  -v $(pwd)/certs:/etc/nginx/certs:ro \
  -v $(pwd)/nginx-tls.conf:/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine

# Test TLS connection
curl -k https://localhost:8443

# Test with CA verification
curl --cacert certs/ca.pem https://localhost:8443
```

**Step 4: Cleanup**
```bash
docker stop nginx-tls
docker rm nginx-tls
cd ..
rm -rf tls-lab
```

### Lab 4.3: Container Firewall Rules

**Objective:** Implement firewall rules for container security

#### For Ubuntu (iptables):

**Step 1: Examine Docker's iptables Rules**
```bash
# View Docker's iptables rules
sudo iptables -L DOCKER-USER
sudo iptables -L DOCKER
sudo iptables -t nat -L DOCKER

# Check Docker chain
sudo iptables -L -n --line-numbers
```

**Step 2: Create Custom Firewall Rules**
```bash
# Allow only specific source networks
sudo iptables -I DOCKER-USER -s 192.168.1.0/24 -j ACCEPT
sudo iptables -I DOCKER-USER -s 10.0.0.0/8 -j ACCEPT

# Block all other external access
sudo iptables -A DOCKER-USER -j DROP

# Create logging rule for blocked traffic
sudo iptables -I DOCKER-USER -j LOG --log-prefix "DOCKER-BLOCK: "

# Test rule with container
docker run -d -p 8080:80 --name firewall-test nginx:alpine

# Test access (should be blocked from unauthorized networks)
curl http://localhost:8080
```

#### For Windows (Windows Firewall):

**Step 1: Configure Windows Firewall Rules**
```powershell
# Create inbound rule for Docker containers
New-NetFirewallRule -DisplayName "Docker Container Access" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8080 `
  -Action Allow `
  -RemoteAddress 192.168.1.0/24

# Block all other access to Docker ports
New-NetFirewallRule -DisplayName "Block Docker External" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8080 `
  -Action Block `
  -RemoteAddress Any

# Test with container
docker run -d -p 8080:80 --name firewall-test nginx:alpine
```

**Step 3: Cleanup (Both Platforms)**
```bash
# Remove test container
docker stop firewall-test
docker rm firewall-test

# Remove custom iptables rules (Ubuntu)
sudo iptables -D DOCKER-USER -s 192.168.1.0/24 -j ACCEPT
sudo iptables -D DOCKER-USER -s 10.0.0.0/8 -j ACCEPT
sudo iptables -D DOCKER-USER -j DROP
```

---

## Knowledge Check Quiz - Section 4

### Question 1 (Multiple Choice)
Which Docker network driver provides the highest level of isolation?

A) bridge
B) host
C) overlay
D) none

**Answer: D**

### Question 2 (True/False)
It's secure to publish container ports using -p 0.0.0.0:3306:3306 for a database container.

**Answer: False** - This exposes the database to all network interfaces; use specific IPs or internal networks.

### Question 3 (Multiple Choice)
What is the primary security benefit of network segmentation in containerized applications?

A) Improved performance
B) Reduced attack surface and lateral movement prevention
C) Easier deployment
D) Better resource utilization

**Answer: B**

### Question 4 (Multiple Choice)
Which command creates an internal Docker network that cannot route to external networks?

A) docker network create --internal mynet
B) docker network create --isolated mynet
C) docker network create --private mynet
D) docker network create --secure mynet

**Answer: A**

### Question 5 (Short Answer)
Name three security features provided by service mesh solutions like Istio or Linkerd.

**Answer:**
1. Automatic mutual TLS (mTLS) encryption
2. Identity-based access control/authorization
3. Traffic monitoring and observability

---

# Section 5: Access Control and Authentication

## Course Slides - Section 5

### Slide 5.1: Docker Daemon Security

**Docker Daemon Attack Surface:**

The Docker daemon runs with root privileges and exposes a powerful API that can control the entire host system.

**Security Risks:**
- **Privilege Escalation** - Daemon runs as root
- **API Exposure** - Unprotected Docker API access
- **Socket Permissions** - Docker socket access = root access
- **Container Escape** - Privileged containers can access host

**Docker Daemon Security Architecture:**
```
┌─────────────────────────────────────────────────────────┐
│                    Host System                         │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐ │
│  │              Docker Daemon (root)                  │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐│ │
│  │  │   REST API  │  │ Image Mgmt  │  │Container Mgmt││ │
│  │  └─────────────┘  └─────────────┘  └──────────────┘│ │
│  └─────────────────────────────────────────────────────┘ │
│           │                    │                         │
│  ┌─────────────┐      ┌─────────────┐                   │
│  │ Unix Socket │      │  TCP Socket │                   │
│  │/var/run/    │      │   :2376     │                   │
│  │docker.sock  │      │  (TLS)      │                   │
│  └─────────────┘      └─────────────┘                   │
└─────────────────────────────────────────────────────────┘
```

**Daemon Security Hardening:**
```bash
# Enable TLS for Docker daemon
dockerd \
  --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=server-cert.pem \
  --tlskey=server-key.pem \
  -H=0.0.0.0:2376

# Configure daemon with security options
{
  "hosts": ["tcp://0.0.0.0:2376"],
  "tls": true,
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem",
  "userland-proxy": false,
  "icc": false,
  "userns-remap": "default"
}
```

### Slide 5.2: User and Group Management

**User Namespace Remapping:**

User namespaces map container users to different host users, providing additional isolation.

**Without User Namespace:**
```
Container Process (UID 0) → Host Process (UID 0) ← ROOT ACCESS
```

**With User Namespace:**
```
Container Process (UID 0) → Host Process (UID 100000) ← UNPRIVILEGED
```

**Configuring User Namespace Remapping:**
```bash
# Enable user namespace in daemon configuration
echo 'dockremap:100000:65536' >> /etc/subuid
echo 'dockremap:100000:65536' >> /etc/subgid

# Configure daemon.json
{
  "userns-remap": "default"
}

# Restart Docker daemon
sudo systemctl restart docker

# Verify mapping
docker run --rm ubuntu id
# Should show UID 0 in container, but different UID on host
```

**Non-root Container Users:**
```dockerfile
# Create and use non-root user in Dockerfile
FROM alpine:3.18

# Create user and group
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Switch to non-root user
USER appuser

# Application runs as appuser (UID 1001)
WORKDIR /app
CMD ["./app"]
```

**Runtime User Override:**
```bash
# Override user at runtime
docker run --user 1001:1001 ubuntu whoami

# Use named user (if exists in container)
docker run --user nobody ubuntu id
```

### Slide 5.3: Role-Based Access Control (RBAC)

**Docker Authorization Plugins:**

Docker supports authorization plugins that can implement fine-grained access control policies.

**RBAC Architecture:**
```
┌─────────────────────────────────────────────────────────┐
│                  Authorization Flow                     │
└─────────────────────────────────────────────────────────┘
         │
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   User/     │───▶│   Docker    │───▶│   Auth      │
│   Client    │    │   Daemon    │    │   Plugin    │
└─────────────┘    └─────────────┘    └─────────────┘
         │                │                │
         │                │                ▼
         │                │       ┌─────────────┐
         │                │       │   Policy    │
         │                │       │   Store     │
         │                │       └─────────────┘
         │                ▼
         │       ┌─────────────┐
         │       │   Action    │
         └──────▶│ Allow/Deny  │
                 └─────────────┘
```

**Example RBAC Policies:**

| Role | Permissions | Resources |
|------|-------------|-----------|
| **Developer** | Read, Run | Images, Containers |
| **DevOps** | Read, Run, Build | All resources |
| **Admin** | Full access | All resources |
| **Read-only** | View only | Logs, Stats |

**Open Policy Agent (OPA) Integration:**
```yaml
# OPA Policy Example
package docker.authz

default allow = false

# Allow developers to run containers
allow {
    input.User == "developer"
    input.RequestedAction == "container_create"
}

# Allow admins full access
allow {
    input.User in {"admin", "devops"}
}

# Deny privileged containers for non-admins
deny {
    not input.User == "admin"
    input.RequestBody.HostConfig.Privileged == true
}
```

### Slide 5.4: Secrets Management

**Container Secrets Challenge:**

Traditional approaches of handling secrets in containers are insecure:

❌ **Insecure Methods:**
- Environment variables (visible in process list)
- Hardcoded in images (persistent in layers)
- Config files in images (version control exposure)
- Command line arguments (visible in logs)

✅ **Secure Methods:**
- External secret management systems
- Runtime secret injection
- Encrypted secret stores
- Short-lived tokens

**Docker Swarm Secrets:**
```bash
# Create a secret
echo "mysecretpassword" | docker secret create db_password -

# Use secret in service
docker service create \
  --name myapp \
  --secret db_password \
  myapp:latest

# Secret mounted at /run/secrets/db_password
```

**External Secret Management Integration:**

```
┌─────────────────────────────────────────────────────────┐
│                External Secret Stores                   │
├─────────────────┬─────────────────┬─────────────────────┤
│   HashiCorp     │   AWS Secrets   │   Azure Key         │
│     Vault       │    Manager      │     Vault           │
└─────────────────┴─────────────────┴─────────────────────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│              Secret Injection Methods                   │
├─────────────────┬─────────────────┬─────────────────────┤
│   Init          │   Sidecar       │   CSI Driver        │
│  Container      │  Container      │   (Kubernetes)      │
└─────────────────┴─────────────────┴─────────────────────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│                Application Container                    │
└─────────────────────────────────────────────────────────┘
```

**Best Practices for Secrets:**
- Use dedicated secret management systems
- Implement secret rotation
- Apply least privilege access
- Audit secret access
- Use short-lived credentials
- Encrypt secrets at rest and in transit

### Slide 5.5: Multi-factor Authentication

**MFA for Container Environments:**

Multi-factor authentication adds security layers beyond just passwords or certificates.

**MFA Components:**
1. **Something you know** - Password, PIN
2. **Something you have** - Token, Certificate, Smart card
3. **Something you are** - Biometric data

**Docker Registry MFA:**
```bash
# Configure registry with OIDC/SAML
version: 0.1
log:
  fields:
    service: registry
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: :5000
auth:
  token:
    realm: https://auth.example.com/token
    service: docker-registry
    issuer: example-auth-service
    rootcertbundle: /etc/registry/auth.crt
```

**Certificate-based Authentication:**
```bash
# Generate client certificate for user
openssl genrsa -out client-key.pem 4096
openssl req -new -key client-key.pem -out client.csr \
  -subj "/CN=user@example.com"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -out client-cert.pem -days 365

# Use client certificate for Docker commands
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=client-cert.pem \
  --tlskey=client-key.pem \
  -H=daemon.example.com:2376 ps
```

**Hardware Security Module (HSM) Integration:**
- Store private keys in tamper-resistant hardware
- Sign container images with HSM-protected keys
- Implement strong key lifecycle management
- Meet compliance requirements (FIPS 140-2)

---

## Hands-on Lab Exercises - Section 5

### Lab 5.1: User Namespace Configuration

**Objective:** Configure and test user namespace remapping for enhanced security

#### For Ubuntu:

**Step 1: Configure User Namespace Remapping**
```bash
# Check current Docker configuration
docker info | grep -i "user namespace"

# Stop Docker daemon
sudo systemctl stop docker

# Configure subuid and subgid
echo 'dockremap:100000:65536' | sudo tee -a /etc/subuid
echo 'dockremap:100000:65536' | sudo tee -a /etc/subgid

# Create or modify daemon.json
sudo mkdir -p /etc/docker
echo '{
  "userns-remap": "default"
}' | sudo tee /etc/docker/daemon.json

# Start Docker daemon
sudo systemctl start docker

# Verify configuration
docker info | grep -i "user namespace"
```

**Step 2: Test User Namespace Mapping**
```bash
# Run container and check process mapping
docker run -d --name usertest nginx:alpine

# Check container process on host
ps aux | grep nginx

# Check user mapping inside container
docker exec usertest id

# Check file ownership mapping
docker exec usertest ls -la /var/log/

# Stop and remove test container
docker stop usertest
docker rm usertest
```

#### For Windows:

User namespace remapping is not directly supported on Windows containers, but similar security can be achieved through:

**Step 1: Windows Container User Configuration**
```powershell
# Run container with specific user (Windows containers)
docker run -it --user ContainerUser mcr.microsoft.com/windows/nanoserver cmd

# Check current user
whoami

# Create custom Dockerfile with non-admin user
```

**Step 2: Cleanup (Ubuntu)**
```bash
# Revert to default configuration
sudo systemctl stop docker
sudo rm /etc/docker/daemon.json
sudo systemctl start docker
```

### Lab 5.2: Docker Daemon TLS Configuration

**Objective:** Secure Docker daemon with TLS authentication

#### For Both Windows and Ubuntu:

**Step 1: Generate TLS Certificates**
```bash
# Create certificate directory
mkdir -p docker-tls
cd docker-tls

# Generate CA key
openssl genrsa -aes256 -out ca-key.pem 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem \
  -subj "/C=US/ST=CA/L=SF/O=Docker/CN=Docker CA"

# Generate server key
openssl genrsa -out server-key.pem 4096

# Generate server certificate request
openssl req -subj "/C=US/ST=CA/L=SF/O=Docker/CN=docker-daemon" \
  -sha256 -new -key server-key.pem -out server.csr

# Create extensions file for server cert
echo "subjectAltName = DNS:localhost,IP:127.0.0.1,IP:0.0.0.0" > extfile.cnf
echo "extendedKeyUsage = serverAuth" >> extfile.cnf

# Generate server certificate
openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem \
  -CAkey ca-key.pem -out server-cert.pem -extfile extfile.cnf -CAcreateserial

# Generate client key
openssl genrsa -out key.pem 4096

# Generate client certificate request
openssl req -subj '/C=US/ST=CA/L=SF/O=Docker/CN=client' \
  -new -key key.pem -out client.csr

# Create extensions file for client cert
echo "extendedKeyUsage = clientAuth" > extfile-client.cnf

# Generate client certificate
openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.pem \
  -CAkey ca-key.pem -out cert.pem -extfile extfile-client.cnf -CAcreateserial

# Set proper permissions
chmod 400 ca-key.pem key.pem server-key.pem
chmod 444 ca.pem server-cert.pem cert.pem
```

**Step 2: Configure Docker Daemon with TLS (Testing)**
```bash
# Stop current Docker daemon (for testing)
sudo systemctl stop docker

# Start Docker daemon with TLS (in background for testing)
sudo dockerd \
  --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=server-cert.pem \
  --tlskey=server-key.pem \
  -H=0.0.0.0:2376 \
  -H unix:///var/run/docker.sock &

# Test TLS connection
docker --tlsverify \
  --tlscacert=ca.pem \
  --tlscert=cert.pem \
  --tlskey=key.pem \
  -H=localhost:2376 version

# Test without proper certificates (should fail)
docker -H=localhost:2376 version
```

**Step 3: Cleanup**
```bash
# Kill test daemon
sudo pkill dockerd

# Restart normal Docker service
sudo systemctl start docker

# Remove certificates
cd ..
rm -rf docker-tls
```

### Lab 5.3: Secrets Management with Docker Swarm

**Objective:** Implement secure secrets management using Docker Swarm

#### For Both Windows and Ubuntu:

**Step 1: Initialize Docker Swarm**
```bash
# Initialize swarm mode
docker swarm init

# Verify swarm status
docker node ls
```

**Step 2: Create and Manage Secrets**
```bash
# Create secrets from command line
echo "mydbpassword123" | docker secret create db_password -
echo "supersecretkey456" | docker secret create api_key -

# Create secret from file
echo "admin:$2y$10$..." > users.htpasswd
docker secret create web_users users.htpasswd

# List secrets
docker secret ls

# Inspect secret (metadata only)
docker secret inspect db_password
```

**Step 3: Use Secrets in Services**

Create `app.py`:
```python
#!/usr/bin/env python3
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

class SecretHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        
        # Read secrets from mounted files
        try:
            with open('/run/secrets/db_password', 'r') as f:
                db_pass = f.read().strip()
            with open('/run/secrets/api_key', 'r') as f:
                api_key = f.read().strip()
            
            response = f"Secrets loaded successfully!\n"
            response += f"DB Password length: {len(db_pass)}\n"
            response += f"API Key length: {len(api_key)}\n"
        except Exception as e:
            response = f"Error reading secrets: {e}\n"
        
        self.wfile.write(response.encode())

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), SecretHandler)
    server.serve_forever()
```

Create `Dockerfile`:
```dockerfile
FROM python:3.9-alpine
COPY app.py /app.py
EXPOSE 8080
CMD ["python", "/app.py"]
```

**Step 4: Deploy Service with Secrets**
```bash
# Build application image
docker build -t secret-app .

# Create service with secrets
docker service create \
  --name secret-service \
  --secret db_password \
  --secret api_key \
  --publish 8080:8080 \
  secret-app

# Test the service
curl http://localhost:8080

# Check secret files in container
docker exec $(docker ps -q -f ancestor=secret-app) ls -la /run/secrets/
docker exec $(docker ps -q -f ancestor=secret-app) cat /run/secrets/db_password
```

**Step 5: Secret Rotation**
```bash
# Create new version of secret
echo "newdbpassword789" | docker secret create db_password_v2 -

# Update service with new secret
docker service update \
  --secret-rm db_password \
  --secret-add db_password_v2 \
  secret-service

# Remove old secret
docker secret rm db_password
```

**Step 6: Cleanup**
```bash
# Remove service
docker service rm secret-service

# Remove secrets
docker secret rm db_password_v2 api_key web_users

# Leave swarm mode
docker swarm leave --force

# Remove files
rm app.py Dockerfile users.htpasswd
```

---

## Knowledge Check Quiz - Section 5

### Question 1 (Multiple Choice)
What is the primary security benefit of user namespace remapping in Docker?

A) Improved container performance
B) Better network isolation
C) Container root user maps to unprivileged host user
D) Faster container startup

**Answer: C**

### Question 2 (True/False)
It's safe to pass secrets to containers using environment variables.

**Answer: False** - Environment variables are visible in process lists and container inspection.

### Question 3 (Multiple Choice)
Which Docker daemon configuration provides the strongest authentication?

A) --host=tcp://0.0.0.0:2376
B) --tlsverify with client certificates
C) --host=unix:///var/run/docker.sock
D) No authentication required

**Answer: B**

### Question 4 (Multiple Choice)
Where are Docker Swarm secrets mounted inside containers by default?

A) /etc/secrets/
B) /var/secrets/
C) /run/secrets/
D) /tmp/secrets/

**Answer: C**

### Question 5 (Short Answer)
List three insecure methods of handling secrets in containers that should be avoided.

**Answer:**
1. Environment variables (visible in process list)
2. Hardcoded in container images (persistent in layers)
3. Command line arguments (visible in logs)

---

# Section 6: Monitoring and Compliance

## Course Slides - Section 6

### Slide 6.1: Security Monitoring and Logging

**Container Security Monitoring Strategy:**

Effective container security requires comprehensive monitoring across multiple layers:

**Monitoring Layers:**
```
┌─────────────────────────────────────────────────────────┐
│                 Application Layer                       │
│           (Application-specific logs)                   │
├─────────────────────────────────────────────────────────┤
│                 Container Layer                         │
│         (Container runtime events)                      │
├─────────────────────────────────────────────────────────┤
│                Orchestration Layer                      │
│         (Kubernetes/Swarm events)                       │
├─────────────────────────────────────────────────────────┤
│                   Host Layer                            │
│            (System and kernel logs)                     │
├─────────────────────────────────────────────────────────┤
│                Infrastructure Layer                     │
│         (Network and hardware events)                   │
└─────────────────────────────────────────────────────────┘
```

**Key Monitoring Areas:**

| Area | What to Monitor | Tools |
|------|-----------------|-------|
| **Container Events** | Start, stop, create, destroy | Docker Events API |
| **Resource Usage** | CPU, memory, disk, network | cAdvisor, Prometheus |
| **File System** | File changes, access patterns | HIDS, auditd |
| **Network Traffic** | Connections, data flows | Network monitoring |
| **Process Activity** | Process creation, system calls | Falco, Sysdig |

**Centralized Logging Architecture:**
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Container A │    │ Container B │    │ Container C │
│   Logs      │    │   Logs      │    │   Logs      │
└─────────────┘    └─────────────┘    └─────────────┘
         │                │                │
         └────────────────┼────────────────┘
                          │
                 ┌─────────────┐
                 │  Log Agent  │
                 │ (Fluentd)   │
                 └─────────────┘
                          │
                 ┌─────────────┐
                 │Log Storage  │
                 │(Elastic-    │
                 │ search)     │
                 └─────────────┘
                          │
                 ┌─────────────┐
                 │Visualization│
                 │  (Kibana)   │
                 └─────────────┘
```

### Slide 6.2: Runtime Threat Detection

**Container Runtime Security Tools:**

**Falco - Runtime Security Monitoring**
```yaml
# Falco rules for container security
- rule: Container with Sensitive Mount
  desc: Detect containers with sensitive host paths mounted
  condition: >
    spawned_process and 
    k8s.pod and 
    fd.name startswith /host
  output: >
    Sensitive mount in container (user=%user.name 
    command=%proc.cmdline pod=%k8s.pod.name)
  priority: WARNING

- rule: Unexpected Network Connection
  desc: Detect unexpected outbound connections
  condition: >
    outbound and 
    not trusted_outbound_networks
  output: >
    Unexpected outbound connection (connection=%fd.name 
    user=%user.name command=%proc.cmdline)
  priority: NOTICE
```

**Behavioral Analysis Patterns:**

| Threat Type | Detection Pattern | Response |
|-------------|------------------|----------|
| **Container Escape** | Syscalls to host filesystem | Alert + Isolate |
| **Cryptocurrency Mining** | High CPU + network activity | Block + Terminate |
| **Data Exfiltration** | Large outbound transfers | Monitor + Alert |
| **Privilege Escalation** | Process spawning as root | Block + Log |

**Runtime Protection Workflow:**
```
Event Detection → Policy Evaluation → Response Action
      │                   │                │
      ▼                   ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  System     │  │   Rules     │  │   Block     │
│  Calls      │  │  Engine     │  │   Alert     │
│  Network    │  │  Policy     │  │   Log       │
│  Activity   │  │  Match      │  │   Isolate   │
└─────────────┘  └─────────────┘  └─────────────┘
```

### Slide 6.3: Compliance Frameworks (CIS, NIST)

**CIS Docker Benchmark:**

The Center for Internet Security (CIS) provides comprehensive security benchmarks for Docker.

**CIS Docker Benchmark Categories:**

1. **Host Configuration** (1.0)
   - 1.1 Ensure a separate partition for containers
   - 1.2 Ensure only trusted users control Docker daemon

2. **Docker Daemon Configuration** (2.0)
   - 2.1 Restrict network traffic between containers
   - 2.2 Set the logging level
   - 2.3 Allow Docker to make changes to iptables

3. **Docker Daemon Configuration Files** (3.0)
   - 3.1 Verify that docker.service file ownership is set to root:root
   - 3.2 Verify that docker.service file permissions are set to 644

4. **Container Images and Build File** (4.0)
   - 4.1 Create a user for the container
   - 4.2 Use trusted base images for containers

5. **Container Runtime** (5.0)
   - 5.1 Do not disable AppArmor Profile
   - 5.2 Verify SELinux security options, if applicable

**NIST Cybersecurity Framework Mapping:**

| NIST Function | Container Security Controls |
|---------------|----------------------------|
| **Identify** | Asset inventory, vulnerability scanning |
| **Protect** | Access controls, encryption, hardening |
| **Detect** | Monitoring, logging, anomaly detection |
| **Respond** | Incident response, isolation procedures |
| **Recover** | Backup/restore, business continuity |

**Automated Compliance Checking:**
```bash
# Docker Bench Security (CIS benchmark)
docker run --rm --net host --pid host --userns host \
  --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security
```

### Slide 6.4: Security Auditing and Reporting

**Container Security Audit Framework:**

**Audit Scope Areas:**
- Image security and vulnerability status
- Runtime configuration compliance
- Access control effectiveness
- Network security posture
- Secrets management practices
- Monitoring and logging coverage

**Security Metrics and KPIs:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Mean Time to Patch** | < 24 hours | Critical vulnerabilities |
| **Image Vulnerability Score** | < 7.0 CVSS | Base images |
| **Compliance Score** | > 95% | CIS benchmark |
| **Incident Response Time** | < 1 hour | Security alerts |
| **Security Training** | 100% | Team completion |

**Automated Reporting Example:**
```python
#!/usr/bin/env python3
import docker
import json
from datetime import datetime

def generate_security_report():
    client = docker.from_env()
    report = {
        "timestamp": datetime.now().isoformat(),
        "containers": [],
        "images": [],
        "networks": [],
        "security_score": 0
    }
    
    # Analyze containers
    for container in client.containers.list():
        container_info = {
            "name": container.name,
            "image": container.image.tags[0] if container.image.tags else "unknown",
            "privileged": container.attrs["HostConfig"]["Privileged"],
            "user": container.attrs["Config"]["User"] or "root",
            "capabilities": container.attrs["HostConfig"]["CapAdd"] or [],
            "security_opt": container.attrs["HostConfig"]["SecurityOpt"] or []
        }
        report["containers"].append(container_info)
    
    # Calculate security score
    total_containers = len(report["containers"])
    secure_containers = sum(1 for c in report["containers"] 
                          if not c["privileged"] and c["user"] != "root")
    
    if total_containers > 0:
        report["security_score"] = (secure_containers / total_containers) * 100
    
    return report

# Generate and save report
if __name__ == "__main__":
    report = generate_security_report()
    with open(f"security_report_{datetime.now().strftime('%Y%m%d')}.json", 'w') as f:
        json.dump(report, f, indent=2)
```

### Slide 6.5: Incident Response

**Container Security Incident Response Plan:**

**Incident Classification:**

| Severity | Examples | Response Time |
|----------|----------|---------------|
| **Critical** | Container escape, data breach | 15 minutes |
| **High** | Privilege escalation, malware | 1 hour |
| **Medium** | Policy violations, misconfigurations | 4 hours |
| **Low** | Minor compliance issues | 24 hours |

**Incident Response Workflow:**
```
Detection → Triage → Containment → Investigation → Recovery → Lessons Learned
    │         │          │             │            │            │
    ▼         ▼          ▼             ▼            ▼            ▼
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐
│Monitoring│ │Severity │ │Isolate  │ │Root     │ │Restore  │ │Process  │
│Alerts   │ │Assessment│ │Container│ │Cause    │ │Service  │ │Improve  │
│Tools    │ │Impact   │ │Stop     │ │Analysis │ │Update   │ │Document │
│         │ │Analysis │ │Spread   │ │Evidence │ │Policy   │ │Train    │
└─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
```

**Container Isolation Procedures:**
```bash
# Immediate container isolation
docker network disconnect <network> <container>
docker pause <container>

# Evidence collection
docker exec <container> ps aux > evidence_processes.txt
docker logs <container> > evidence_logs.txt
docker export <container> > evidence_filesystem.tar

# Complete isolation
docker stop <container>
docker network rm <compromised_network>
```

---

## Hands-on Lab Exercises - Section 6

### Lab 6.1: Security Monitoring Setup

**Objective:** Set up comprehensive security monitoring for containers

#### For Both Windows and Ubuntu:

**Step 1: Install and Configure Docker Events Monitoring**
```bash
# Monitor Docker events in real-time
docker events &

# In another terminal, create container activity
docker run -d --name monitor-test nginx:alpine
docker stop monitor-test
docker rm monitor-test

# Check events output
```

**Step 2: Container Resource Monitoring**
```bash
# Start monitoring containers with resource limits
docker run -d --name resource-monitor \
  --memory=256m \
  --cpus="0.5" \
  --restart=unless-stopped \
  nginx:alpine

# Monitor resource usage
docker stats resource-monitor

# Generate load to test monitoring
docker exec resource-monitor sh -c "while true; do echo test; done" &

# Stop load generation
docker exec resource-monitor pkill sh

# Cleanup
docker stop resource-monitor
docker rm resource-monitor
```

**Step 3: Log Aggregation Setup**

Create `docker-compose.yml` for ELK stack:
```yaml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.15.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    networks:
      - elk

  logstash:
    image: docker.elastic.co/logstash/logstash:7.15.0
    ports:
      - "5044:5044"
    networks:
      - elk
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:7.15.0
    ports:
      - "5601:5601"
    networks:
      - elk
    depends_on:
      - elasticsearch

networks:
  elk:
    driver: bridge
```

```bash
# Deploy monitoring stack
docker-compose up -d

# Verify services
docker-compose ps

# Check Kibana (may take a few minutes to start)
curl http://localhost:5601

# Cleanup
docker-compose down
```

### Lab 6.2: CIS Benchmark Assessment

**Objective:** Run CIS Docker Benchmark assessment

#### For Ubuntu:

**Step 1: Download and Run Docker Bench Security**
```bash
# Clone Docker Bench Security
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security

# Run the benchmark
sudo ./docker-bench-security.sh

# Run with JSON output
sudo ./docker-bench-security.sh -l /tmp/docker-bench.log -j > docker-bench-results.json

# Review results
cat docker-bench-results.json | jq '.tests[] | select(.result == "WARN")'
```

**Step 2: Fix Common Issues**
```bash
# Example fixes for common CIS findings

# 1. Create non-root user for containers
docker run --user 1001:1001 nginx:alpine

# 2. Set resource limits
docker run --memory=512m --cpus="1.0" nginx:alpine

# 3. Enable content trust
export DOCKER_CONTENT_TRUST=1

# 4. Use read-only root filesystem
docker run --read-only --tmpfs /tmp nginx:alpine

# 5. Drop capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx:alpine
```

#### For Windows:

**Step 1: Manual CIS Assessment**
```powershell
# Check Docker daemon configuration
docker version
docker info

# Review Windows-specific security settings
Get-Service docker
Get-Process dockerd

# Check container isolation
docker run mcr.microsoft.com/windows/nanoserver cmd /c "whoami"
```

**Step 3: Create Remediation Report**
```bash
# Create remediation tracking
cat > remediation_plan.md << 'EOF'
# Docker Security Remediation Plan

## High Priority Items
- [ ] Configure user namespace remapping
- [ ] Enable Docker Content Trust
- [ ] Implement resource limits for all containers
- [ ] Configure AppArmor/SELinux profiles

## Medium Priority Items  
- [ ] Update base images to latest versions
- [ ] Implement network segmentation
- [ ] Configure centralized logging

## Low Priority Items
- [ ] Enable additional audit logging
- [ ] Document security procedures
EOF

# Cleanup
cd ..
rm -rf docker-bench-security
```

### Lab 6.3: Runtime Threat Detection with Falco

**Objective:** Deploy and configure Falco for runtime security monitoring

#### For Ubuntu:

**Step 1: Install Falco**
```bash
# Add Falco repository
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | sudo apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list

# Update and install
sudo apt-get update
sudo apt-get install -y falco

# Verify installation
falco --version
```

**Step 2: Configure Custom Falco Rules**

Create `/etc/falco/rules.d/custom_rules.yaml`:
```yaml
# Custom Docker security rules
- rule: Suspicious Container Activity
  desc: Detect suspicious process execution in containers
  condition: >
    spawned_process and 
    container and 
    (proc.name in (nc, ncat, netcat, nmap, socat, ss, lsof))
  output: >
    Suspicious network tool in container (user=%user.name 
    command=%proc.cmdline container=%container.name 
    image=%container.image.repository)
  priority: WARNING
  tags: [network, container]

- rule: Container Root Login
  desc: Detect interactive root login in containers
  condition: >
    spawned_process and 
    container and 
    proc.name in (bash, sh, zsh) and 
    user.name=root
  output: >
    Root shell spawned in container (user=%user.name 
    command=%proc.cmdline container=%container.name)
  priority: NOTICE
  tags: [shell, container]

- rule: Sensitive File Access
  desc: Detect access to sensitive files from containers
  condition: >
    open_read and 
    container and 
    fd.name in (/etc/passwd, /etc/shadow, /etc/ssh/ssh_host_rsa_key)
  output: >
    Sensitive file accessed from container (file=%fd.name 
    container=%container.name user=%user.name)
  priority: WARNING
  tags: [filesystem, container]
```

**Step 3: Run Falco and Generate Test Events**
```bash
# Start Falco in background
sudo falco -r /etc/falco/rules.d/custom_rules.yaml &

# Generate test events
# Trigger suspicious network tool detection
docker run --rm -it ubuntu bash -c "apt-get update && apt-get install -y netcat && nc -l 8080" &

# Trigger root shell detection
docker run --rm -it ubuntu bash

# Trigger sensitive file access
docker run --rm -it ubuntu cat /etc/passwd

# Check Falco logs
sudo journalctl -u falco -f
```

**Step 4: Cleanup**
```bash
# Stop Falco
sudo pkill falco

# Remove custom rules
sudo rm /etc/falco/rules.d/custom_rules.yaml
```

### Lab 6.4: Incident Response Simulation

**Objective:** Practice container security incident response procedures

#### For Both Windows and Ubuntu:

**Step 1: Create Simulated Compromised Container**
```bash
# Create a "compromised" container scenario
docker run -d --name compromised-app \
  --privileged \
  --network host \
  --pid host \
  --volume /:/host:rw \
  ubuntu:latest sleep 3600

# Simulate malicious activity
docker exec compromised-app bash -c "
  # Simulate crypto mining
  while true; do echo 'mining crypto' > /dev/null; done &
  
  # Simulate data exfiltration attempt
  find /host/home -name '*.txt' 2>/dev/null | head -10 > /tmp/stolen_files.txt
  
  # Simulate privilege escalation attempt
  chroot /host /bin/bash -c 'id' 2>/dev/null
"
```

**Step 2: Detection and Initial Response**
```bash
# Detect suspicious container
docker ps --filter "name=compromised"

# Check container configuration
docker inspect compromised-app | grep -A 5 -B 5 "Privileged\|SecurityOpt"

# Monitor resource usage
docker stats compromised-app --no-stream

# Check processes in container
docker exec compromised-app ps aux
```

**Step 3: Containment Procedures**
```bash
# Immediate isolation - disconnect from networks
docker network ls
for net in $(docker inspect compromised-app -f '{{range .NetworkSettings.Networks}}{{.NetworkID}} {{end}}'); do
    echo "Disconnecting from network: $net"
    docker network disconnect $net compromised-app 2>/dev/null || true
done

# Pause container to stop execution
docker pause compromised-app

# Verify container is paused
docker ps -f "name=compromised-app"
```

**Step 4: Evidence Collection**
```bash
# Create evidence directory
mkdir -p incident_$(date +%Y%m%d_%H%M%S)
cd incident_$(date +%Y%m%d_%H%M%S)

# Collect container logs
docker logs compromised-app > container_logs.txt

# Export container filesystem for analysis
docker export compromised-app > container_filesystem.tar

# Collect process information
docker exec compromised-app ps aux > process_list.txt 2>/dev/null || echo "Container paused" > process_list.txt

# Collect network connections (if unpaused temporarily)
docker unpause compromised-app
docker exec compromised-app netstat -tulpn > network_connections.txt 2>/dev/null || true
docker pause compromised-app

# Collect container configuration
docker inspect compromised-app > container_config.json

# Create incident report
cat > incident_report.md << 'EOF'
# Container Security Incident Report

## Incident Details
- **Container Name:** compromised-app
- **Detection Time:** $(date)
- **Severity:** High
- **Type:** Privileged container with host access

## Indicators of Compromise
- Privileged container with host filesystem access
- High CPU usage (simulated crypto mining)
- File system enumeration activities
- Privilege escalation attempts

## Actions Taken
1. Container isolated from networks
2. Container execution paused
3. Evidence collected
4. Awaiting forensic analysis

## Recommendations
- Implement runtime security monitoring
- Enforce non-privileged container policies
- Regular security scanning and compliance checks
EOF
```

**Step 5: Recovery and Cleanup**
```bash
# Complete container removal
docker unpause compromised-app
docker stop compromised-app
docker rm compromised-app

# Verify cleanup
docker ps -a | grep compromised || echo "Container successfully removed"

# Archive evidence
cd ..
tar -czf incident_evidence_$(date +%Y%m%d_%H%M%S).tar.gz incident_*

# Cleanup evidence directory
rm -rf incident_*

echo "Incident response simulation completed"
```

---

## Knowledge Check Quiz - Section 6

### Question 1 (Multiple Choice)
Which tool is specifically designed for runtime security monitoring of containers?

A) Docker Bench Security
B) Falco
C) Trivy
D) Docker Scout

**Answer: B**

### Question 2 (True/False)
The CIS Docker Benchmark only covers container runtime security, not host configuration.

**Answer: False** - CIS Docker Benchmark covers host configuration, daemon configuration, and runtime security.

### Question 3 (Multiple Choice)
What is the recommended maximum response time for critical container security incidents?

A) 1 hour
B) 4 hours
C) 15 minutes
D) 24 hours

**Answer: C**

### Question 4 (Multiple Choice)
Which command immediately isolates a running container from network access?

A) docker stop <container>
B) docker pause <container>
C) docker network disconnect <network> <container>
D) docker rm <container>

**Answer: C**

### Question 5 (Short Answer)
Name three types of evidence that should be collected during a container security incident.

**Answer:**
1. Container logs (docker logs)
2. Container filesystem (docker export)
3. Container configuration (docker inspect)

---

# Section 7: Production Deployment Security

## Course Slides - Section 7

### Slide 7.1: Kubernetes Security Integration

**Container Security in Kubernetes:**

Kubernetes adds orchestration-level security controls on top of container security.

**Kubernetes Security Architecture:**
```
┌─────────────────────────────────────────────────────────┐
│                 Kubernetes Control Plane               │
├─────────────────┬─────────────────┬─────────────────────┤
│   API Server    │    etcd         │   Controller        │
│   (RBAC,        │  (Encryption    │    Manager          │
│   Admission     │   at Rest)      │  (Pod Security)     │
│   Controllers)  │                 │                     │
└─────────────────┴─────────────────┴─────────────────────┘
         │                 │                 │
┌─────────────────────────────────────────────────────────┐
│                    Worker Nodes                        │
├─────────────────┬─────────────────┬─────────────────────┤
│    kubelet      │   Container     │    Network          │
│  (Pod Security  │   Runtime       │    Policies         │
│   Standards)    │  (Isolation)    │  (NetworkPolicy)    │
└─────────────────┴─────────────────┴─────────────────────┘
```

**Pod Security Standards:**

| Level | Description | Use Case |
|-------|-------------|----------|
| **Privileged** | No restrictions | Trusted workloads only |
| **Baseline** | Minimal restrictions | Standard applications |
| **Restricted** | Heavily restricted | Security-sensitive apps |

**Example Pod Security Policy:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE
    resources:
      limits:
        memory: "512Mi"
        cpu: "500m"
      requests:
        memory: "256Mi"
        cpu: "250m"
```

### Slide 7.2: CI/CD Pipeline Security

**Secure Container CI/CD Pipeline:**

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Source    │───▶│   Build     │───▶│    Test     │───▶│   Deploy    │
│   Control   │    │   Image     │    │  & Scan     │    │    Prod     │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                   │                   │                   │
      ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│• Git hooks  │    │• Secure     │    │• Vuln scan  │    │• Signed     │
│• Code scan  │    │  Dockerfile │    │• Policy     │    │  images     │
│• Secrets    │    │• Multi-stage│    │  check      │    │• Runtime    │
│  detection  │    │  build      │    │• Security   │    │  security   │
│             │    │• Base image │    │  test       │    │• Monitoring │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

**Pipeline Security Controls:**

**1. Source Code Security:**
- Static Application Security Testing (SAST)
- Dependency scanning
- Secret detection
- Code signing

**2. Build Security:**
- Secure build environments
- Reproducible builds
- Build artifact signing
- Supply chain verification

**3. Image Security:**
- Vulnerability scanning
- Policy compliance checking
- Image signing
- Registry security

**4. Deployment Security:**
- Runtime policy enforcement
- Security context validation
- Network policy application
- Continuous monitoring

**Example GitLab CI Security Pipeline:**
```yaml
stages:
  - security-scan
  - build
  - test
  - security-test
  - deploy

sast:
  stage: security-scan
  image: registry.gitlab.com/gitlab-org/security-products/analyzers/semgrep:latest
  script:
    - semgrep --config=auto --json --output=sast-report.json .
  artifacts:
    reports:
      sast: sast-report.json

secret-detection:
  stage: security-scan
  image: registry.gitlab.com/gitlab-org/security-products/analyzers/secrets:latest
  script:
    - /analyzer run
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json

build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

container-scanning:
  stage: security-test
  image: registry.gitlab.com/gitlab-org/security-products/analyzers/container-scanning:latest
  script:
    - gtcs scan $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
```

### Slide 7.3: Infrastructure as Code Security

**Secure IaC for Container Deployments:**

**IaC Security Principles:**
- Version control all infrastructure definitions
- Implement security policy as code
- Automate security compliance checking
- Use least privilege access principles
- Enable audit logging and monitoring

**Terraform Security Example:**
```hcl
# Secure container infrastructure
resource "aws_ecs_cluster" "secure_cluster" {
  name = "secure-app-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
      
      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs.name
      }
    }
  }
}

resource "aws_ecs_task_definition" "secure_app" {
  family                   = "secure-app"
  requires_compatibilities = ["FARGATE"]
  network_mode            = "awsvpc"
  cpu                     = 256
  memory                  = 512
  execution_role_arn      = aws_iam_role.ecs_execution_role.arn
  task_role_arn          = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([{
    name  = "app"
    image = "myregistry.com/myapp:latest"
    
    # Security configurations
    user = "1001:1001"
    readonlyRootFilesystem = true
    
    linuxParameters = {
      capabilities = {
        drop = ["ALL"]
        add  = ["NET_BIND_SERVICE"]
      }
    }
    
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.app.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])
}
```

**IaC Security Scanning Tools:**
- **Checkov** - Static analysis for Terraform, CloudFormation
- **Terrascan** - Policy as code framework
- **Bridgecrew** - Cloud security posture management
- **Snyk IaC** - Infrastructure as code scanning

### Slide 7.4: Final Assessment and Best Practices Review

**Container Security Best Practices Summary:**

**Image Security:**
✅ Use minimal, trusted base images
✅ Implement multi-stage builds
✅ Regular vulnerability scanning
✅ Sign and verify images
✅ Use specific version tags

**Runtime Security:**
✅ Run as non-root users
✅ Apply resource limits
✅ Use read-only filesystems
✅ Drop unnecessary capabilities
✅ Enable security profiles (AppArmor/SELinux)

**Network Security:**
✅ Implement network segmentation
✅ Use TLS for communications
✅ Apply network policies
✅ Monitor network traffic
✅ Secure service-to-service communications

**Access Control:**
✅ Implement RBAC
✅ Use secrets management
✅ Enable audit logging
✅ Apply principle of least privilege
✅ Multi-factor authentication

**Monitoring & Compliance:**
✅ Runtime threat detection
✅ Centralized logging
✅ Compliance automation
✅ Incident response procedures
✅ Regular security assessments

**Security Maturity Model:**

| Level | Characteristics | Timeline |
|-------|----------------|----------|
| **Level 1 - Basic** | Manual security, basic scanning | 0-3 months |
| **Level 2 - Managed** | Automated scanning, policies | 3-6 months |
| **Level 3 - Defined** | Integrated security, monitoring | 6-12 months |
| **Level 4 - Measured** | Metrics, continuous improvement | 12+ months |
| **Level 5 - Optimized** | Adaptive security, AI/ML integration | 18+ months |

---

## Final Hands-on Lab Exercise

### Lab 7.1: Complete Security Pipeline Implementation

**Objective:** Implement a complete secure container deployment pipeline

#### For Both Windows and Ubuntu:

**Step 1: Create Secure Application**

Create `app.py`:
```python
#!/usr/bin/env python3
import os
from flask import Flask, jsonify
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "user": os.getenv("USER", "unknown")})

@app.route('/secure')
def secure():
    # Read secret from mounted file
    try:
        with open('/run/secrets/api_key', 'r') as f:
            key_length = len(f.read().strip())
        return jsonify({"message": "Secure endpoint", "key_length": key_length})
    except FileNotFoundError:
        return jsonify({"message": "Secret not found"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

Create `requirements.txt`:
```
Flask==2.3.3
Werkzeug==2.3.7
```

**Step 2: Create Secure Multi-stage Dockerfile**
```dockerfile
# Multi-stage build for security
FROM python:3.11-alpine AS builder

# Install dependencies in builder stage
WORKDIR /build
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-alpine AS production

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy only necessary files from builder
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appgroup app.py /app/

# Security configurations
USER appuser
WORKDIR /app
ENV PATH=/home/appuser/.local/bin:$PATH

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Use exec form
CMD ["python", "app.py"]
```

**Step 3: Create Security Policy Configuration**

Create `k8s-deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  labels:
    app: secure-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 1001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: secure-app:latest
        imagePullPolicy: Never
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        resources:
          limits:
            memory: "256Mi"
            cpu: "250m"
          requests:
            memory: "128Mi"
            cpu: "100m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        - name: secret-volume
          mountPath: /run/secrets
          readOnly: true
      volumes:
      - name: tmp-volume
        emptyDir: {}
      - name: secret-volume
        secret:
          secretName: app-secrets
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  api_key: c3VwZXJzZWNyZXRrZXkxMjM=  # base64: supersecretkey123
---
apiVersion: v1
kind: Service
metadata:
  name: secure-app-service
spec:
  selector:
    app: secure-app
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
```

**Step 4: Build and Security Scan**
```bash
# Build the secure image
docker build -t secure-app:latest .

# Scan for vulnerabilities
docker scout cves secure-app:latest

# Run local security checks
docker run --rm \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --user 1001:1001 \
  --read-only \
  --tmpfs /tmp \
  -p 8080:8080 \
  secure-app:latest &

# Test the application
sleep 10
curl http://localhost:8080/health
curl http://localhost:8080/secure

# Stop test container
docker stop $(docker ps -q --filter ancestor=secure-app:latest)
```

**Step 5: Deploy with Kubernetes (if available)**
```bash
# Apply the secure deployment
kubectl apply -f k8s-deployment.yaml

# Verify deployment
kubectl get pods -l app=secure-app
kubectl describe pod -l app=secure-app

# Test service
kubectl port-forward service/secure-app-service 8080:80 &
curl http://localhost:8080/health

# Check security context
kubectl exec -it deployment/secure-app -- id
kubectl exec -it deployment/secure-app -- ps aux

# Cleanup
kubectl delete -f k8s-deployment.yaml
pkill kubectl
```

**Step 6: Security Validation Report**
```bash
# Create comprehensive security report
cat > security_validation_report.md << 'EOF'
# Container Security Validation Report

## Image Security ✅
- [x] Multi-stage build implemented
- [x] Non-root user configured (UID 1001)
- [x] Minimal base image (Alpine)
- [x] No secrets in image layers
- [x] Specific version tags used
- [x] Vulnerability scanning passed

## Runtime Security ✅
- [x] Read-only root filesystem
- [x] All capabilities dropped
- [x] Resource limits applied
- [x] Security context configured
- [x] Health checks implemented
- [x] Proper secret management

## Network Security ✅
- [x] ClusterIP service (internal only)
- [x] Minimal port exposure (8080 only)
- [x] No privileged networking
- [x] Network policies ready

## Access Control ✅
- [x] Non-root user enforcement
- [x] Secrets mounted securely
- [x] Principle of least privilege
- [x] RBAC ready deployment

## Monitoring & Compliance ✅
- [x] Health monitoring configured
- [x] Structured logging implemented
- [x] Resource monitoring enabled
- [x] Security validation automated

## Overall Security Score: 95/100

### Recommendations for Production:
1. Implement network policies
2. Add runtime security monitoring (Falco)
3. Enable audit logging
4. Implement image signing
5. Add automated compliance checking
EOF

echo "Security validation completed successfully!"
cat security_validation_report.md
```

---

## Final Assessment Quiz

### Question 1 (Multiple Choice)
Which Kubernetes security feature provides the most comprehensive pod-level security controls?

A) NetworkPolicy
B) Pod Security Standards
C) RBAC
D) Service Mesh

**Answer: B**

### Question 2 (True/False)
It's acceptable to store secrets in container environment variables if they are encrypted at rest.

**Answer: False** - Environment variables are visible in process lists and container inspection, regardless of encryption at rest.

### Question 3 (Multiple Choice)
What is the primary benefit of multi-stage Dockerfile builds for security?

A) Faster build times
B) Smaller final images with reduced attack surface
C) Better caching
D) Easier debugging

**Answer: B**

### Question 4 (Multiple Choice)
Which CI/CD security practice is most critical for container security?

A) Fast deployment times
B) Automated rollbacks
C) Vulnerability scanning before deployment
D) Blue-green deployments

**Answer: C**

### Question 5 (Short Answer)
List the five key security layers that should be implemented in a production container deployment.

**Answer:**
1. Image Security (secure base images, vulnerability scanning)
2. Runtime Security (non-root users, resource limits, security contexts)
3. Network Security (segmentation, TLS, network policies)
4. Access Control (RBAC, secrets management, authentication)
5. Monitoring & Compliance (logging, threat detection, compliance automation)

---

## Course Completion

**Congratulations!** You have completed the Docker Security Course. You should now be able to:

✅ Understand container security fundamentals and threat landscape
✅ Implement secure image building and management practices
✅ Configure runtime security controls and isolation mechanisms
✅ Design and implement secure container networking
✅ Establish proper access control and authentication systems
✅ Deploy comprehensive monitoring and compliance frameworks
✅ Integrate security throughout the container development lifecycle

**Next Steps:**
1. Practice these skills in your own environment
2. Stay updated with latest security threats and mitigations
3. Consider advanced certifications (CKS, Docker Security)
4. Implement continuous security improvements
5. Share knowledge with your team and organization

**Additional Resources:**
- Docker Security Documentation
- OWASP Container Security Guide
- CIS Docker Benchmark
- Kubernetes Security Best Practices
- NIST Container Security Guidelines