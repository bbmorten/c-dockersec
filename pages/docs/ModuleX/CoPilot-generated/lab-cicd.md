# Lab: Secure CI/CD Pipeline (Ubuntu 24.04 Guide)

## Objective
Integrate security checks into a CI/CD pipeline for Docker images, using practical tools and configuration on Ubuntu 24.04.

## Prerequisites
- Ubuntu 24.04 system (VM or bare metal)
- Docker Engine installed (`sudo apt update && sudo apt install docker.io -y`)
- Git installed (`sudo apt install git -y`)
- (Optional) GitHub account and repository, or local GitLab/Jenkins setup
- Trivy installed (`sudo apt install trivy -y`)

## Lab Steps

1. **Set Up a Sample Project and Git Repository**
   - Create a new directory and initialize a Git repo:
     ```bash
     mkdir docker-cicd-demo && cd docker-cicd-demo
     git init
     ```
   - Add a simple Dockerfile:
     ```dockerfile
     FROM node:18-alpine
     WORKDIR /app
     COPY . .
     RUN npm install --production && rm -rf /tmp/*
     USER node
     CMD ["node", "app.js"]
     ```
   - Commit your files:
     ```bash
     git add .
     git commit -m "Initial commit"
     ```

2. **Add a Security Scan Step to the CI/CD Pipeline**
   - For GitHub Actions, create `.github/workflows/docker-security.yml`:
     ```yaml
     name: Docker Security Scan
     on: [push]
     jobs:
       scan:
         runs-on: ubuntu-latest
         steps:
           - uses: actions/checkout@v3
           - name: Build Docker image
             run: docker build -t mynode:ci .
           - name: Run Trivy scan
             uses: aquasecurity/trivy-action@master
             with:
               image-ref: mynode:ci
     ```
   - For GitLab CI, add to `.gitlab-ci.yml`:
     ```yaml
     stages:
       - build
       - scan
     build:
       script:
         - docker build -t mynode:ci .
     scan:
       image: aquasec/trivy:latest
       script:
         - trivy image mynode:ci
     ```

3. **Configure Pipeline to Fail on Critical Vulnerabilities**
   - Trivy and most scanners return a non-zero exit code if critical vulns are found, causing the pipeline to fail automatically.
   - You can customize severity thresholds in Trivy with `--severity HIGH,CRITICAL`.

4. **Add Automated Dockerfile Best Practice Checks**
   - Use Hadolint for Dockerfile linting:
     ```bash
     docker run --rm -i hadolint/hadolint < Dockerfile
     ```
   - Add this as a step in your pipeline.

5. **Document Your Pipeline and Results**
   - Save your pipeline configuration files and a sample scan report.
   - Note any vulnerabilities found and how the pipeline responded.

## Deliverable
Submit your pipeline configuration files, a sample scan report, and a summary of security checks performed and their results.
