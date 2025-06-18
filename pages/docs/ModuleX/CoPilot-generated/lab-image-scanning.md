# Lab: Image Scanning and Hardening (Ubuntu 24.04 Guide)

## Objective
Scan Docker images for vulnerabilities and apply hardening techniques using practical tools on Ubuntu 24.04.

## Prerequisites
- Ubuntu 24.04 system (VM or bare metal)
- Docker Engine installed (`sudo apt update && sudo apt install docker.io -y`)
- Trivy installed (`sudo apt install trivy -y` or see https://aquasecurity.github.io/trivy/v0.50.0/getting-started/installation/)
- (Optional) Snyk CLI installed (`npm install -g snyk`)

## Lab Steps

1. **Pull a Sample Vulnerable Docker Image**
   - Example: Pull an intentionally vulnerable Node.js image:
     ```bash
     docker pull vulnerables/node:8
     ```

2. **Scan the Image for Vulnerabilities**
   - Using Trivy:
     ```bash
     trivy image vulnerables/node:8
     ```
   - (Optional) Using Snyk:
     ```bash
     snyk container test vulnerables/node:8
     ```
   - Review the output for high/critical vulnerabilities.

3. **Document and Prioritize Findings**
   - List the top 3-5 most critical vulnerabilities found (CVE, severity, package).
   - Example table:

| CVE           | Severity | Package      | Description                |
|---------------|----------|--------------|----------------------------|
| CVE-2019-5736 | HIGH     | runc         | Container breakout         |
| CVE-2018-1000654 | CRITICAL | openssl   | Remote code execution      |

4. **Harden the Dockerfile**
   - Download the sample Dockerfile (or create your own):
     ```bash
     wget https://raw.githubusercontent.com/vulnerables/node-exploit/master/Dockerfile
     nano Dockerfile
     ```
   - Apply at least two hardening steps:
     - Use a minimal base image (e.g., `node:18-alpine` instead of `node:8`)
     - Remove unnecessary packages and files
     - Set a non-root user (`USER node`)
     - Avoid copying secrets into the image
   - Example change:
     ```dockerfile
     FROM node:18-alpine
     WORKDIR /app
     COPY . .
     RUN npm install --production && rm -rf /tmp/*
     USER node
     CMD ["node", "app.js"]
     ```

5. **Rebuild and Re-Scan the Hardened Image**
   - Build the new image:
     ```bash
     docker build -t mynode:secure .
     ```
   - Scan again:
     ```bash
     trivy image mynode:secure
     ```
   - Compare the vulnerability report to the original scan.

## Deliverable
Submit your vulnerability report (before and after hardening) and the improved Dockerfile.
