# Module 2 Key Topics: Securing Docker Images

## Writing Secure Dockerfiles
- Use minimal base images (e.g., Alpine) to reduce attack surface.
- Apply multi-stage builds to separate build and runtime environments.
- Avoid running as root; specify a non-root user.

**Diagram: Multi-Stage Build**

```dockerfile
FROM node:18 AS build
WORKDIR /app
COPY . .
RUN npm install && npm run build

FROM node:18-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
CMD ["node", "dist/app.js"]
```

**References:**
- [Docker Docs: Best practices for writing Dockerfiles](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [OWASP: Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

## Image Provenance and Trust
- Pull images from trusted registries and verify signatures.
- Use Docker Content Trust and Notary for image verification.

**Diagram: Image Pull and Verification**

```
[Docker Hub] --(signed image)--> [Your Host]
      |                             |
  (Notary) <--- signature check ---|
```

**References:**
- [Docker Docs: Content Trust](https://docs.docker.com/engine/security/trust/)
- [Notary Project](https://github.com/theupdateframework/notary)

## Vulnerability Scanning
- Scan images with Trivy, Snyk, or Clair to detect known vulnerabilities.
- Interpret scan results and prioritize remediation.

**Diagram: Image Scanning Workflow**

```
[Docker Image] --> [Trivy/Snyk/Clair] --> [Vulnerability Report]
```

**References:**
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Snyk Container Scanning](https://snyk.io/product/container-vulnerability-scanner/)
- [Clair Project](https://github.com/quay/clair)

## Managing Secrets and Sensitive Data
- Avoid hardcoding secrets in Dockerfiles or images.
- Use Docker secrets or environment variables securely.

**Diagram: Docker Secrets**

```
[Secret] --> [Docker Swarm/Compose] --> [Container ENV or File]
```

**References:**
- [Docker Docs: Manage sensitive data with Docker secrets](https://docs.docker.com/engine/swarm/secrets/)
- [12 Factor App: Config](https://12factor.net/config)

## Dependency and Patch Management
- Keep images and dependencies up to date.
- Automate rebuilds and scans to catch new vulnerabilities.

**References:**
- [Docker Docs: Keeping Images Up to Date](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#leverage-build-cache)
- [Snyk: Container Patch Management](https://snyk.io/blog/container-patch-management/)
