# Course Syllabus: Docker Security

## Modules Overview

1. **Module 1: Introduction to Docker Security**
2. **Module 2: Securing Docker Images**
3. **Module 3: Runtime Security and Hardening**
4. **Module 4: Network Security for Containers**
5. **Module 5: Monitoring, Logging, and Incident Response**
6. **Module 6: CI/CD Security and Compliance**

---

## Module Details

### Module 1: Introduction to Docker Security
- **Learning Objectives:**
  - Understand the container security model and threat landscape
  - Identify common vulnerabilities in containerized environments
- **Key Topics:**
  - Containers vs. virtual machines: security boundaries and risks
  - Docker architecture: components and attack surfaces (daemon, socket, images)
  - Real-world container security breaches and lessons learned (e.g., Tesla Kubernetes breach)
  - The shared kernel model and implications for isolation
  - Overview of the container threat landscape (supply chain, runtime, network)
- **Estimated Time:** 3 hours
- **Activities/Resources:**
  - Video lectures, reading assignments, discussion forum
  - [Lab: Threat Modeling Docker Environments](lab-intro-threat-modeling.md)
  - [Quiz: Docker Security Fundamentals](quiz-intro.md)

### Module 2: Securing Docker Images
- **Learning Objectives:**
  - Harden Docker images and minimize attack surface
  - Use image scanning tools to detect vulnerabilities
- **Key Topics:**
  - Writing secure Dockerfiles: best practices (minimal base images, multi-stage builds, non-root users)
  - Image provenance: trusted registries, image signing, and verification
  - Vulnerability scanning with Trivy, Snyk, and Clair
  - Managing secrets and sensitive data in images
  - Handling software dependencies and patching
- **Estimated Time:** 4 hours
- **Activities/Resources:**
  - Hands-on Dockerfile hardening
  - [Lab: Image Scanning and Hardening](lab-image-scanning.md)
  - [Quiz: Image Security](quiz-image.md)

### Module 3: Runtime Security and Hardening
- **Learning Objectives:**
  - Apply runtime security controls and policies
  - Use Linux security modules (AppArmor, SELinux, seccomp)
- **Key Topics:**
  - User namespaces, capabilities, and privilege management
  - Seccomp, AppArmor, and SELinux: configuring and applying profiles
  - Resource limits (CPU, memory, disk) and container isolation
  - Runtime monitoring tools (Falco, Sysdig)
  - Detecting and responding to suspicious container behavior
- **Estimated Time:** 4 hours
- **Activities/Resources:**
  - Policy configuration exercises
  - [Lab: Seccomp and AppArmor Profiles](lab-runtime-profiles.md)
  - [Quiz: Runtime Security](quiz-runtime.md)

### Module 4: Network Security for Containers
- **Learning Objectives:**
  - Secure container networking and control traffic
  - Implement network segmentation and firewall rules
- **Key Topics:**
  - Docker networking modes (bridge, host, overlay, macvlan)
  - Network segmentation and isolation strategies
  - Implementing firewalls and network policies (iptables, Cilium)
  - TLS encryption for container communication
  - Secrets management for network credentials
- **Estimated Time:** 4 hours
- **Activities/Resources:**
  - Network policy labs
  - [Lab: Network Segmentation](lab-network-segmentation.md)
  - [Quiz: Network Security](quiz-network.md)

### Module 5: Monitoring, Logging, and Incident Response
- **Learning Objectives:**
  - Monitor container activity and detect threats
  - Respond to security incidents in containerized environments
- **Key Topics:**
  - Logging best practices for containers (stdout/stderr, log drivers)
  - Intrusion detection and runtime monitoring (Falco, auditd)
  - Incident response workflows and forensics in Docker
  - Collecting and analyzing container logs and events
  - Automating alerts and responses to suspicious activity
- **Estimated Time:** 4 hours
- **Activities/Resources:**
  - Log analysis exercises
  - [Lab: Container Incident Response](lab-incident-response.md)
  - [Quiz: Monitoring & IR](quiz-monitoring.md)

### Module 6: CI/CD Security and Compliance
- **Learning Objectives:**
  - Integrate security into CI/CD pipelines
  - Ensure compliance with industry standards
- **Key Topics:**
  - Secure build and deployment pipelines (GitHub Actions, GitLab CI, Jenkins)
  - Automated security testing and vulnerability scanning in CI/CD
  - Compliance frameworks: CIS Docker Benchmark, NIST, PCI DSS
  - Policy enforcement and compliance gates in pipelines
  - Supply chain security and image provenance
- **Estimated Time:** 5 hours
- **Activities/Resources:**
  - Pipeline security labs
  - [Lab: Secure CI/CD Pipeline](lab-cicd.md)
  - [Quiz: CI/CD & Compliance](quiz-cicd.md)
