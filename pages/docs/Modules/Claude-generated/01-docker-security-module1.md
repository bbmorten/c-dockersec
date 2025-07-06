# Module 1: Container Security Foundations and Threat Landscape

## Module Overview
Duration: 4 hours  
Format: Video lectures (2 hours), Hands-on labs (1.5 hours), Assessment (30 minutes)

## Learning Path

### Pre-Module Checklist
- [ ] Docker installed and running
- [ ] Linux environment ready (VM or WSL2)
- [ ] Downloaded module resources
- [ ] Completed pre-module reading

---

## Section 1.1: Docker Architecture Deep Dive (45 minutes)

### Video Lecture Content

#### Introduction to Container Security Architecture

Welcome to Module 1! Before we can secure containers, we must understand how they work at a fundamental level. Containers are not virtual machines – they share the host kernel, which brings both performance benefits and unique security challenges.

**Key Concepts:**

1. **Containers vs. Virtual Machines**
   - VMs: Hardware virtualization, separate OS kernel, strong isolation
   - Containers: OS-level virtualization, shared kernel, process isolation
   - Security implications: Smaller attack surface but shared kernel risks

2. **The Docker Architecture**
   ```
   Docker Client → Docker Daemon → Container Runtime → Linux Kernel
        ↓               ↓                    ↓              ↓
     CLI/API      Image Management     runC/containerd   Namespaces
                  Network Setup         Container Lifecycle  cgroups
                  Volume Management     Process Management   Capabilities
   ```

#### Linux Namespaces: The Foundation of Isolation

Namespaces provide isolated views of system resources. Docker uses six types:

1. **PID Namespace** (Process Isolation)
   ```bash
   # Demo: Process isolation
   docker run -it --rm alpine sh
   # Inside container:
   ps aux  # Only shows container processes
   # PID 1 is the container's init process
   ```

2. **Network Namespace** (Network Isolation)
   - Separate network stack per container
   - Own IP addresses, routing tables, network devices
   - Communication through virtual bridges

3. **Mount Namespace** (Filesystem Isolation)
   - Containers see their own root filesystem
   - Host filesystem hidden from container view
   - Bind mounts create controlled sharing

4. **UTS Namespace** (Hostname Isolation)
   - Each container has its own hostname
   - Prevents information leakage

5. **IPC Namespace** (Inter-Process Communication)
   - Isolates System V IPC and POSIX message queues
   - Prevents cross-container IPC attacks

6. **User Namespace** (User/Group ID Mapping)
   - Maps container root to non-root on host
   - Critical for reducing privilege escalation risks

#### Control Groups (cgroups): Resource Management and Security

Cgroups limit and account for resource usage:

```bash
# View container cgroup limits
docker run -d --name test --memory="512m" --cpus="1.0" nginx
cat /sys/fs/cgroup/memory/docker/$(docker inspect test -f '{{.Id}}')/memory.limit_in_bytes
```

**Security Benefits:**
- Prevents DoS through resource exhaustion
- Ensures fair resource allocation
- Enables detection of abnormal resource usage

#### Linux Capabilities: Fine-Grained Privileges

Traditional Unix: binary root/non-root distinction  
Capabilities: Decomposed root privileges into ~40 distinct units

**Default Docker Capabilities:**
```bash
# List capabilities for a container
docker run --rm alpine sh -c 'apk add -q libcap; capsh --print'
```

**Dropped by Default:**
- CAP_SYS_ADMIN (broad system administration)
- CAP_SYS_MODULE (kernel module loading)
- CAP_SYS_RAWIO (raw I/O operations)
- CAP_SYS_PTRACE (process tracing)
- CAP_DAC_READ_SEARCH (bypass file read permissions)

### Lab 1.1: Exploring Namespace Isolation

**Objective:** Understand how namespaces provide isolation between containers and the host.

**Setup:**
```bash
# Create working directory
mkdir -p ~/docker-security/module1
cd ~/docker-security/module1
```

**Exercise 1: PID Namespace Isolation**
```bash
# Step 1: Check host processes
ps aux | wc -l
echo "Host PID 1: $(ps -p 1 -o comm=)"

# Step 2: Run container and check processes
docker run -it --name pid-test alpine sh
# Inside container:
ps aux
echo "Container PID 1: $(ps -p 1 -o comm=)"
exit

# Step 3: Demonstrate isolation breach (privileged mode) - SECURITY RISK!
docker run -it --rm --privileged --pid=host alpine sh
# Inside container:
ps aux | wc -l  # Now shows all host processes!
exit
```

**Exercise 2: Network Namespace Isolation**
```bash
# Step 1: Check host network interfaces
ip addr show

# Step 2: Run container and check its network
docker run -it --rm alpine sh
# Inside container:
ip addr show  # Different interfaces
ping -c 2 google.com  # Still has internet via NAT
exit

# Step 3: Run isolated container
docker run -it --rm --network none alpine sh
# Inside container:
ip addr show  # Only loopback
ping google.com  # Fails - no network access
exit
```

**Exercise 3: User Namespace Mapping**
```bash
# Step 1: Default behavior (root in container = root on host)
docker run -it --rm alpine sh
# Inside container:
id  # uid=0(root)
echo "malicious" > /tmp/test
exit

# Step 2: With user namespace (if enabled)
# First, check if user namespaces are enabled
docker info | grep "User Namespaces"

# If enabled, create userns-remap
sudo mkdir -p /etc/docker
echo '{"userns-remap": "default"}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker

# Run container with user namespace
docker run -it --rm alpine sh
# Inside container:
id  # Still shows uid=0 inside
# But on host, processes run as remapped user
```

### Section 1.2: Container Threat Landscape (45 minutes)

#### Common Container Attack Vectors

1. **Image-Based Attacks**
   - Malicious base images
   - Embedded secrets and credentials
   - Outdated/vulnerable packages
   - Supply chain attacks

2. **Runtime Attacks**
   - Container escape/breakout
   - Privilege escalation
   - Resource exhaustion
   - Kernel exploits

3. **Network Attacks**
   - Container-to-container lateral movement
   - Host network exposure
   - Service discovery exploitation
   - Man-in-the-middle attacks

4. **Storage Attacks**
   - Volume permission vulnerabilities
   - Sensitive data exposure
   - Persistent malware via volumes

#### Container Threat Modeling

**STRIDE Framework Applied to Containers:**

| Threat | Container Context | Example |
|--------|------------------|---------|
| **S**poofing | Image authenticity | Pulling malicious images |
| **T**ampering | Runtime modification | Modifying container filesystem |
| **R**epudiation | Audit trail gaps | Unlogged container actions |
| **I**nformation Disclosure | Secret exposure | Environment variables with passwords |
| **D**enial of Service | Resource exhaustion | Fork bombs, memory leaks |
| **E**levation of Privilege | Container escape | Kernel exploits, misconfigurations |

#### Real-World Container Security Incidents

1. **Tesla Kubernetes Hack (2018)**
   - Unsecured Kubernetes dashboard
   - Cryptomining in containers
   - Lesson: Secure management interfaces

2. **Docker Hub Breach (2019)**
   - 190,000 accounts compromised
   - Supply chain implications
   - Lesson: Image signing importance

3. **Azurescape (2021)**
   - Cross-tenant container escape
   - Cloud provider vulnerability
   - Lesson: Shared responsibility model

### Lab 1.2: Container Threat Demonstration

**Exercise 1: Container Escape via Privileged Mode**

```bash
# WARNING: This demonstrates a security vulnerability
# Only run in isolated lab environment

# Step 1: Create a "vulnerable" container
docker run -it --rm --privileged ubuntu bash

# Inside container - escape to host:
# Mount host filesystem
mkdir /host
mount /proc/1/ns/mnt /host

# Access host filesystem
chroot /host
# You now have root access to the host!
exit
exit
```

**Exercise 2: Capability Exploitation**

```bash
# Create container with extra capabilities
docker run -it --rm --cap-add=SYS_ADMIN ubuntu bash

# Inside container:
# Show we have SYS_ADMIN
capsh --print | grep sys_admin

# Mount host proc (security risk!)
mount -t proc none /proc
# Can now see host processes in certain scenarios
exit
```

**Exercise 3: Secret Exposure in Images**

```bash
# Create a "bad" Dockerfile
cat > Dockerfile.insecure << EOF
FROM alpine
ENV API_KEY=super_secret_key_12345
ENV DATABASE_PASSWORD=admin123
RUN echo "password123" > /root/.pgpass
CMD ["/bin/sh"]
EOF

# Build and inspect
docker build -f Dockerfile.insecure -t insecure-app .
docker history insecure-app --no-trunc
docker run --rm insecure-app env | grep -E "API_KEY|DATABASE"

# Demonstrate secret extraction
docker save insecure-app | tar -xO --wildcards '*/layer.tar' | strings | grep -E "secret|password"
```

### Section 1.3: Docker Daemon Security (45 minutes)

#### The Docker Daemon Attack Surface

The Docker daemon runs with root privileges and exposes several attack vectors:

1. **API Endpoint Security**
   - Unix socket: `/var/run/docker.sock`
   - TCP socket: Disabled by default (good!)
   - Access = root equivalent on host

2. **Image Processing Vulnerabilities**
   - Image parsing bugs
   - Archive extraction flaws
   - Build context hijacking

3. **Network Configuration Risks**
   - iptables manipulation
   - Bridge network exposure
   - DNS hijacking potential

#### Securing the Docker Daemon

**Best Practices:**

1. **Never Expose Docker TCP Socket Without TLS**
   ```bash
   # INSECURE - Never do this in production!
   # dockerd -H tcp://0.0.0.0:2375
   
   # SECURE - With TLS
   dockerd \
     --tlsverify \
     --tlscacert=ca.pem \
     --tlscert=server-cert.pem \
     --tlskey=server-key.pem \
     -H=0.0.0.0:2376
   ```

2. **Use Socket Permissions**
   ```bash
   # Check docker socket permissions
   ls -la /var/run/docker.sock
   # srw-rw---- 1 root docker
   
   # Add user to docker group (grants root-equivalent access!)
   sudo usermod -aG docker $USER
   ```

3. **Enable Content Trust**
   ```bash
   # Enforce signed images only
   export DOCKER_CONTENT_TRUST=1
   docker pull alpine  # Only pulls if signed
   ```

### Lab 1.3: Docker Daemon Security Testing

**Exercise 1: Docker Socket Exposure Risks**

```bash
# Demonstrate why docker socket access = root
docker run -it --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  docker:dind sh

# Inside container:
# We can control the host's Docker daemon!
docker ps  # Shows host containers
docker run -it --rm --privileged --pid=host alpine nsenter -t 1 -m -u -i -n sh
# You're now root on the host!
exit
exit
```

**Exercise 2: Rootless Docker Setup**

```bash
# Install rootless Docker (Ubuntu/Debian)
sudo apt-get install -y uidmap
curl -fsSL https://get.docker.com/rootless | sh

# Start rootless Docker
systemctl --user start docker

# Set environment
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock
docker version  # Should show rootless mode

# Test isolation
docker run -it --rm alpine sh
# Inside container:
id  # Shows root, but it's not real root
exit
```

### Section 1.4: Kernel Security Features (45 minutes)

#### Security-Enhanced Linux (SELinux)

SELinux provides mandatory access control (MAC) for containers:

```bash
# Check SELinux status
getenforce

# View container SELinux context
docker run -d --name selinux-test nginx
ps -eZ | grep nginx

# SELinux and volumes
docker run -it --rm -v /home/$USER:/data:Z alpine sh
# :Z flag relabels for container access
```

#### AppArmor Integration

AppArmor provides application-level security profiles:

```bash
# Check if AppArmor is enabled
sudo aa-status

# View Docker's default AppArmor profile
sudo cat /etc/apparmor.d/docker-default

# Run container with custom AppArmor profile
docker run --rm --security-opt apparmor=docker-default alpine sh
```

#### Seccomp Profiles

Seccomp filters system calls at kernel level:

```bash
# Docker's default seccomp profile blocks ~44 of ~300 syscalls
# View default profile
docker run --rm alpine sh -c 'echo "Syscalls work normally"'

# Run without seccomp (insecure!)
docker run --rm --security-opt seccomp=unconfined alpine sh

# Create custom seccomp profile
cat > minimal-seccomp.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "exit", "sigreturn"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF

# Test restricted profile
docker run --rm --security-opt seccomp=minimal-seccomp.json alpine echo "test"
# Fails - echo needs more syscalls!
```

### Lab 1.4: Comprehensive Security Lab

**Scenario:** Secure a vulnerable application deployment

**Starting Point:**
```bash
# Deploy intentionally vulnerable app
cat > docker-compose.vulnerable.yml << 'EOF'
version: '3'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
    privileged: true
    environment:
      - API_KEY=secret123
    volumes:
      - /:/host
      - /var/run/docker.sock:/var/run/docker.sock
  db:
    image: mysql:5.7
    environment:
      - MYSQL_ROOT_PASSWORD=root
      - MYSQL_ALLOW_EMPTY_PASSWORD=yes
    ports:
      - "3306:3306"
EOF

docker-compose -f docker-compose.vulnerable.yml up -d
```

**Your Task:** Identify and fix all security issues

**Solution:**
```bash
# Secure version
cat > docker-compose.secure.yml << 'EOF'
version: '3'
services:
  web:
    image: nginx:alpine  # Minimal base image
    ports:
      - "127.0.0.1:8080:80"  # Bind to localhost only
    read_only: true  # Read-only root filesystem
    tmpfs:
      - /var/cache/nginx
      - /var/run
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    user: "101:101"  # Run as nginx user
    networks:
      - frontend
  
  db:
    image: mysql:8.0  # Updated version
    environment:
      - MYSQL_ROOT_PASSWORD_FILE=/run/secrets/db_root_password
      - MYSQL_DATABASE=app
    secrets:
      - db_root_password
    expose:
      - "3306"  # Not published to host
    networks:
      - backend
    volumes:
      - db_data:/var/lib/mysql
    security_opt:
      - no-new-privileges:true

networks:
  frontend:
  backend:

volumes:
  db_data:

secrets:
  db_root_password:
    file: ./db_root_password.txt
EOF

# Create secret file
echo "$(openssl rand -base64 32)" > db_root_password.txt

# Deploy secure version
docker-compose -f docker-compose.secure.yml up -d
```

## Section 1.5: Module Assessment (30 minutes)

### Knowledge Check Quiz

1. **Which Linux namespace provides process isolation in containers?**
   - a) Network namespace
   - b) PID namespace ✓
   - c) User namespace
   - d) Mount namespace

2. **What capability allows a container to load kernel modules?**
   - a) CAP_NET_ADMIN
   - b) CAP_SYS_ADMIN
   - c) CAP_SYS_MODULE ✓
   - d) CAP_DAC_OVERRIDE

3. **Which of the following is NOT a default dropped capability in Docker?**
   - a) CAP_NET_BIND_SERVICE ✓
   - b) CAP_SYS_ADMIN
   - c) CAP_SYS_MODULE
   - d) CAP_SYS_TIME

4. **What makes the Docker daemon a security concern?**
   - a) It runs with root privileges ✓
   - b) It uses encrypted communication
   - c) It isolates containers
   - d) It limits resources

5. **Which security feature filters system calls?**
   - a) AppArmor
   - b) SELinux
   - c) Seccomp ✓
   - d) Capabilities

### Practical Challenge

**Challenge: Container Escape CTF**

Set up a vulnerable container and try to escape to the host using learned techniques. Document:
1. The vulnerability exploited
2. Steps to reproduce
3. Mitigation strategies

### Reflection Questions

1. How do containers differ from VMs in terms of security isolation?
2. What are the most critical security risks in your current container deployments?
3. Which kernel security feature would be most valuable in your environment?

## Module Summary

### Key Takeaways

1. **Containers are NOT Security Boundaries by Default**
   - Shared kernel = shared risk
   - Proper configuration essential
   - Defense in depth required

2. **The Principle of Least Privilege**
   - Drop unnecessary capabilities
   - Run as non-root when possible
   - Minimize container permissions

3. **Security is a Shared Responsibility**
   - Platform provider secures infrastructure
   - You secure the containers and applications
   - Regular updates and monitoring essential

### Next Steps

- Review all lab exercises
- Complete the assessment
- Prepare for Module 2: Securing Docker Images and Registries

### Additional Resources

1. **Further Reading:**
   - [Docker Security Documentation](https://docs.docker.com/engine/security/)
   - [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
   - [NIST Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

2. **Tools to Explore:**
   - Docker Bench for Security
   - Lynis security auditing
   - Falco runtime security

3. **Community Resources:**
   - Docker Security Team Blog
   - Cloud Native Security Slack
   - r/docker security discussions

---

## Appendix: Command Reference

### Namespace Commands
```bash
# List namespaces
lsns

# Enter namespace
nsenter -t <PID> -n -m -p -i -u sh

# Unshare namespace
unshare --pid --fork bash
```

### Capability Commands
```bash
# View process capabilities
getpcaps <PID>

# Decode capability sets
capsh --decode=<hex_value>

# Run with specific capabilities
capsh --drop=cap_chown -- -c "command"
```

### Security Tool Commands
```bash
# AppArmor
aa-status
aa-complain <profile>
aa-enforce <profile>

# SELinux
getenforce
setenforce [0|1]
chcon -t container_file_t <file>

# Seccomp
# No direct commands - configured via Docker
```

### Docker Security Commands
```bash
# Security scanning
docker scan <image>

# View image layers
docker history <image> --no-trunc

# Export image for analysis
docker save <image> | tar -tv

# Security options
docker run --security-opt <option> <image>
docker run --cap-drop ALL --cap-add <capability> <image>
docker run --read-only <image>
```

This completes Module 1 of the Docker Security course. The content provides a solid foundation for understanding container security principles and prepares students for the more advanced topics in subsequent modules.