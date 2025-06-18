# Module 2: Securing Docker Images and Registries

## Module Overview
Duration: 5 hours  
Format: Video lectures (2.5 hours), Hands-on labs (2 hours), Assessment (30 minutes)

## Learning Path

### Pre-Module Checklist
- [ ] Completed Module 1 and assessment
- [ ] Docker and Docker Compose installed
- [ ] Access to Docker Hub account
- [ ] Installed security scanning tools (instructions provided)
- [ ] Git configured for signing commits

---

## Section 2.1: Secure Image Building Practices (60 minutes)

### Video Lecture Content

#### The Image Security Lifecycle

Container images are the foundation of your security posture. A vulnerable or compromised image affects every container instance. We must secure images at every stage:

1. **Build Time**: Secure Dockerfile practices
2. **Storage Time**: Registry security and signing
3. **Runtime**: Vulnerability scanning and updates
4. **Retirement**: Secure deletion and rotation

#### Dockerfile Security Best Practices

**Principle 1: Minimal Base Images**

```dockerfile
# BAD: Large attack surface
FROM ubuntu:latest
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    netcat

# GOOD: Minimal attack surface
FROM python:3.9-alpine
# Alpine Linux ~5MB vs Ubuntu ~72MB base
```

**Principle 2: Non-Root Users**

```dockerfile
# BAD: Running as root
FROM node:16
COPY app.js .
CMD ["node", "app.js"]

# GOOD: Dedicated user
FROM node:16-alpine
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
COPY --chown=nodejs:nodejs app.js .
USER nodejs
CMD ["node", "app.js"]
```

**Principle 3: Multi-Stage Builds**

```dockerfile
# Build stage - includes compilers, build tools
FROM golang:1.19 AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .

# Final stage - minimal runtime
FROM scratch
COPY --from=builder /build/app /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 8080
ENTRYPOINT ["/app"]
```

**Principle 4: Layer Optimization and Secret Management**

```dockerfile
# BAD: Secrets in layers
FROM alpine
RUN wget --user=admin --password=secret https://private.repo/file
RUN rm ~/.wgetrc  # Too late! Secret is in previous layer

# GOOD: Build-time secrets (Docker 18.09+)
FROM alpine
RUN --mount=type=secret,id=repo_creds \
    wget --user=$(cat /run/secrets/repo_creds | cut -d: -f1) \
         --password=$(cat /run/secrets/repo_creds | cut -d: -f2) \
         https://private.repo/file

# Build with: docker build --secret id=repo_creds,src=creds.txt .
```

**Principle 5: Image Hardening**

```dockerfile
# Complete hardened example
FROM node:16-alpine AS builder
WORKDIR /build
COPY package*.json ./
RUN npm ci --only=production

FROM node:16-alpine
RUN apk add --no-cache dumb-init
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
WORKDIR /app
COPY --from=builder --chown=nodejs:nodejs /build/node_modules ./node_modules
COPY --chown=nodejs:nodejs . .
USER nodejs
EXPOSE 3000
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node healthcheck.js
```

### Lab 2.1: Building Secure Images

**Setup:**
```bash
mkdir -p ~/docker-security/module2/lab1
cd ~/docker-security/module2/lab1
```

**Exercise 1: Base Image Comparison**

```bash
# Create test Dockerfiles
cat > Dockerfile.ubuntu << 'EOF'
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
CMD ["curl", "--version"]
EOF

cat > Dockerfile.alpine << 'EOF'
FROM alpine:latest
RUN apk add --no-cache curl
CMD ["curl", "--version"]
EOF

cat > Dockerfile.distroless << 'EOF'
FROM curlimages/curl:latest
ENTRYPOINT ["curl"]
CMD ["--version"]
EOF

# Build all three
docker build -f Dockerfile.ubuntu -t curl:ubuntu .
docker build -f Dockerfile.alpine -t curl:alpine .
docker build -f Dockerfile.distroless -t curl:distroless .

# Compare sizes
docker images | grep curl

# Analyze attack surface
docker run --rm aquasec/trivy image curl:ubuntu
docker run --rm aquasec/trivy image curl:alpine
docker run --rm aquasec/trivy image curl:distroless

# Check what's inside
docker run --rm curl:ubuntu sh -c 'find /usr/bin /bin -type f | wc -l'
docker run --rm curl:alpine sh -c 'find /usr/bin /bin -type f 2>/dev/null | wc -l'
# distroless has no shell!
```

**Exercise 2: User Security Implementation**

```bash
# Create vulnerable app
cat > app.js << 'EOF'
const http = require('http');
const fs = require('fs');

const server = http.createServer((req, res) => {
    // Vulnerable: Can read any file!
    if (req.url.startsWith('/read/')) {
        const file = req.url.substring(6);
        try {
            const content = fs.readFileSync(file, 'utf8');
            res.writeHead(200);
            res.end(content);
        } catch (err) {
            res.writeHead(404);
            res.end('File not found');
        }
    } else {
        res.writeHead(200);
        res.end(`Running as UID: ${process.getuid()}\n`);
    }
});

server.listen(3000, () => {
    console.log('Server running on port 3000');
});
EOF

# Insecure Dockerfile
cat > Dockerfile.insecure << 'EOF'
FROM node:16
WORKDIR /app
COPY app.js .
EXPOSE 3000
CMD ["node", "app.js"]
EOF

# Secure Dockerfile
cat > Dockerfile.secure << 'EOF'
FROM node:16-alpine
RUN addgroup -g 1001 -S appuser && \
    adduser -S appuser -u 1001
WORKDIR /app
COPY --chown=appuser:appuser app.js .
USER appuser
EXPOSE 3000
CMD ["node", "app.js"]
EOF

# Build and test both
docker build -f Dockerfile.insecure -t app:insecure .
docker build -f Dockerfile.secure -t app:secure .

# Test insecure (can read host files via volume)
docker run -d --name insecure -p 3001:3000 -v /etc:/host-etc:ro app:insecure
curl localhost:3001/  # Shows UID 0 (root)
curl localhost:3001/read//host-etc/passwd  # Can read sensitive files!
docker stop insecure && docker rm insecure

# Test secure
docker run -d --name secure -p 3002:3000 -v /etc:/host-etc:ro app:secure
curl localhost:3002/  # Shows UID 1001
curl localhost:3002/read//host-etc/shadow  # Permission denied!
docker stop secure && docker rm secure
```

**Exercise 3: Multi-Stage Build Optimization**

```bash
# Create a Go application
cat > main.go << 'EOF'
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        hostname, _ := os.Hostname()
        fmt.Fprintf(w, "Hello from %s\n", hostname)
    })
    
    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
EOF

# Single-stage build (BAD)
cat > Dockerfile.singlestage << 'EOF'
FROM golang:1.19
WORKDIR /app
COPY main.go .
RUN go build -o server main.go
CMD ["./server"]
EOF

# Multi-stage build (GOOD)
cat > Dockerfile.multistage << 'EOF'
# Build stage
FROM golang:1.19-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /build
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo -o server main.go

# Runtime stage
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]
EOF

# Build both
docker build -f Dockerfile.singlestage -t goapp:singlestage .
docker build -f Dockerfile.multistage -t goapp:multistage .

# Compare sizes and vulnerabilities
docker images | grep goapp
docker run --rm aquasec/trivy image goapp:singlestage
docker run --rm aquasec/trivy image goapp:multistage

# Test functionality
docker run -d --name single -p 8081:8080 goapp:singlestage
docker run -d --name multi -p 8082:8080 goapp:multistage
curl localhost:8081
curl localhost:8082
docker stop single multi && docker rm single multi
```

### Section 2.2: Image Scanning and Vulnerability Management (60 minutes)

#### Understanding Container Vulnerabilities

**Common Vulnerability Sources:**
1. **OS Packages**: Outdated system libraries
2. **Application Dependencies**: npm, pip, gem packages
3. **Base Image**: Inherited vulnerabilities
4. **Configuration**: Misconfigurations and weak defaults

#### Vulnerability Scanning Tools Comparison

| Tool | Type | Features | Best For |
|------|------|----------|----------|
| **Trivy** | Open Source | Fast, comprehensive, easy setup | General use |
| **Clair** | Open Source | API-driven, database backend | CI/CD integration |
| **Snyk** | Commercial | Developer-focused, fix advice | Development teams |
| **Twistlock/Prisma** | Commercial | Runtime protection, compliance | Enterprise |
| **Anchore** | Open Source/Commercial | Policy engine, detailed analysis | Compliance-focused |

#### Implementing Vulnerability Scanning

**Scanner Installation:**
```bash
# Install Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Or use Docker
alias trivy="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy"
```

**Scanning Strategies:**

1. **Build-Time Scanning**
```bash
# Scan during build
docker build -t myapp:latest .
trivy image --exit-code 1 --severity HIGH,CRITICAL myapp:latest
```

2. **Registry Scanning**
```bash
# Scan images in registry
trivy image registry.example.com/myapp:latest
```

3. **Runtime Scanning**
```bash
# Scan running containers
docker ps --format "table {{.Image}}" | tail -n +2 | xargs -I {} trivy image {}
```

### Lab 2.2: Vulnerability Scanning Pipeline

**Exercise 1: Comprehensive Image Scanning**

```bash
cd ~/docker-security/module2/lab2

# Create vulnerable application
cat > requirements.txt << 'EOF'
flask==0.12.2
requests==2.19.1
PyYAML==3.13
django==1.11.0
EOF

cat > app.py << 'EOF'
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return "Vulnerable app v1.0"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

cat > Dockerfile.vulnerable << 'EOF'
FROM python:3.6
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
CMD ["python", "app.py"]
EOF

# Build vulnerable image
docker build -f Dockerfile.vulnerable -t vulnerable-app:latest .

# Scan with multiple tools
echo "=== Trivy Scan ==="
trivy image --severity HIGH,CRITICAL vulnerable-app:latest

# Export results in different formats
trivy image -f json -o trivy-report.json vulnerable-app:latest
trivy image -f table vulnerable-app:latest > trivy-report.txt

# Create scanning script
cat > scan-image.sh << 'EOF'
#!/bin/bash
IMAGE=$1
SEVERITY=${2:-"HIGH,CRITICAL"}

echo "Scanning $IMAGE for $SEVERITY vulnerabilities..."

# Run scan
SCAN_RESULT=$(trivy image --exit-code 0 --severity $SEVERITY --format json $IMAGE)

# Parse results
VULN_COUNT=$(echo $SCAN_RESULT | jq '[.Results[].Vulnerabilities | length] | add')
CRITICAL_COUNT=$(echo $SCAN_RESULT | jq '[.Results[].Vulnerabilities[] | select(.Severity=="CRITICAL")] | length')
HIGH_COUNT=$(echo $SCAN_RESULT | jq '[.Results[].Vulnerabilities[] | select(.Severity=="HIGH")] | length')

echo "Found $VULN_COUNT vulnerabilities:"
echo "  - CRITICAL: $CRITICAL_COUNT"
echo "  - HIGH: $HIGH_COUNT"

# Generate report
echo $SCAN_RESULT | jq -r '.Results[].Vulnerabilities[] | "\(.Severity): \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion) (\(.Title))"' | sort -u

# Exit with error if critical vulnerabilities found
if [ $CRITICAL_COUNT -gt 0 ]; then
    echo "FAIL: Critical vulnerabilities detected!"
    exit 1
fi

echo "PASS: No critical vulnerabilities found"
exit 0
EOF

chmod +x scan-image.sh
./scan-image.sh vulnerable-app:latest
```

**Exercise 2: Fixing Vulnerabilities**

```bash
# Create fixed version
cat > requirements-fixed.txt << 'EOF'
flask==2.2.2
requests==2.28.1
PyYAML==6.0
django==4.1.3
EOF

cat > Dockerfile.fixed << 'EOF'
FROM python:3.11-slim
RUN groupadd -r appuser && useradd -r -g appuser appuser
WORKDIR /app
COPY requirements-fixed.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
USER appuser
EXPOSE 5000
CMD ["python", "app.py"]
EOF

# Build and scan fixed version
docker build -f Dockerfile.fixed -t vulnerable-app:fixed .
./scan-image.sh vulnerable-app:fixed

# Compare scan results
echo "=== Vulnerability Comparison ==="
echo "Original image:"
trivy image vulnerable-app:latest | grep "Total:"
echo "Fixed image:"
trivy image vulnerable-app:fixed | grep "Total:"
```

**Exercise 3: Automated Scanning in CI/CD**

```bash
# Create GitHub Actions workflow
cat > .github-workflow-security.yml << 'EOF'
name: Container Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Build image
      run: docker build -t ${{ github.repository }}:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ github.repository }}:${{ github.sha }}
        format: 'sarif'
        output: 'trivy-results.sarif'
        severity: 'CRITICAL,HIGH'
        exit-code: '1'
    
    - name: Upload Trivy scan results to GitHub Security
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: 'trivy-results.sarif'
    
    - name: Run Snyk vulnerability scanner
      uses: snyk/actions/docker@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      with:
        image: ${{ github.repository }}:${{ github.sha }}
        args: --severity-threshold=high
EOF

# Create GitLab CI pipeline
cat > .gitlab-ci-security.yml << 'EOF'
stages:
  - build
  - scan
  - deploy

variables:
  IMAGE_NAME: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

build:
  stage: build
  script:
    - docker build -t $IMAGE_NAME .
    - docker push $IMAGE_NAME

container_scanning:
  stage: scan
  image: 
    name: aquasec/trivy:latest
    entrypoint: [""]
  script:
    - trivy image --exit-code 0 --format template --template "@contrib/gitlab.tpl" -o gl-container-scanning-report.json $IMAGE_NAME
    - trivy image --exit-code 1 --severity HIGH,CRITICAL $IMAGE_NAME
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json
  allow_failure: true

deploy:
  stage: deploy
  script:
    - echo "Deploying secure image..."
  only:
    - main
  dependencies:
    - container_scanning
EOF
```

### Section 2.3: Docker Content Trust and Image Signing (75 minutes)

#### Understanding Docker Content Trust (DCT)

Docker Content Trust provides cryptographic signing of images using The Update Framework (TUF). It ensures:

1. **Image Integrity**: Images haven't been tampered with
2. **Publisher Authentication**: Images come from trusted sources
3. **Freshness Guarantees**: Protects against replay attacks

#### How DCT Works

```
Publisher                     Registry                    Consumer
    |                            |                           |
    |-- 1. Push image ---------> |                           |
    |-- 2. Generate keys ------> |                           |
    |-- 3. Sign metadata ------> |                           |
    |                            |<-- 4. Pull image ---------|
    |                            |--- 5. Verify signature --->|
    |                            |--- 6. Download image ---->|
```

#### Implementing Docker Content Trust

### Lab 2.3: Image Signing and Verification

**Exercise 1: Setting Up Docker Content Trust**

```bash
cd ~/docker-security/module2/lab3

# Generate signing keys
# Root key: Manages other keys (keep super secure!)
# Targets key: Signs image tags
# Snapshot key: Signs snapshot metadata
# Timestamp key: Provides freshness

# Enable Docker Content Trust
export DOCKER_CONTENT_TRUST=1

# Initialize repository with signing
docker trust key generate my-signer
docker trust signer add --key my-signer.pub my-signer myregistry/myapp

# Build and sign an image
cat > Dockerfile.signed << 'EOF'
FROM alpine:3.17
RUN apk add --no-cache curl
LABEL version="1.0.0"
LABEL security.scan="passed"
CMD ["curl", "--version"]
EOF

docker build -t myregistry/myapp:1.0.0 -f Dockerfile.signed .

# Push with signing (will prompt for passphrase)
docker push myregistry/myapp:1.0.0

# Verify trust data
docker trust inspect --pretty myregistry/myapp:1.0.0

# Try pulling without DCT
export DOCKER_CONTENT_TRUST=0
docker pull myregistry/myapp:1.0.0  # Works

# Try pulling with DCT
export DOCKER_CONTENT_TRUST=1
docker pull myregistry/myapp:1.0.0  # Verifies signature first
```

**Exercise 2: Advanced Signing Workflows**

```bash
# Create signing infrastructure
mkdir -p ~/.docker/trust/private

# Generate root key separately
docker trust key generate root-key --dir ~/.docker/trust/private

# Create delegation for CI/CD
docker trust signer add --key ci-signer.pub ci-signer myregistry/myapp
docker trust sign myregistry/myapp:1.0.0

# Rotate keys
docker trust key rotate myregistry/myapp --key timestamp
docker trust key rotate myregistry/myapp --key snapshot

# Create policy for automated signing
cat > trust-policy.json << 'EOF'
{
  "version": "1.0",
  "trust": {
    "enabled": true,
    "signers": {
      "ci-system": {
        "keys": ["ci-signer"],
        "repos": ["myregistry/*"]
      },
      "release-team": {
        "keys": ["release-signer"],
        "repos": ["myregistry/prod-*"]
      }
    }
  }
}
EOF

# Implement Notary for advanced workflows
# Notary provides more control over TUF
docker run -d \
  --name notary-server \
  -p 4443:4443 \
  -v notary-server-data:/var/lib/notary \
  notary:server

docker run -d \
  --name notary-signer \
  -p 7899:7899 \
  -v notary-signer-data:/var/lib/notary \
  notary:signer
```

**Exercise 3: Signature Verification in CI/CD**

```bash
# Create verification script
cat > verify-image.sh << 'EOF'
#!/bin/bash
IMAGE=$1

# Enable DCT
export DOCKER_CONTENT_TRUST=1
export DOCKER_CONTENT_TRUST_SERVER=https://notary.example.com

echo "Verifying signatures for $IMAGE..."

# Check if image is signed
if docker trust inspect $IMAGE >/dev/null 2>&1; then
    echo "✓ Image is signed"
    
    # Get signer information
    SIGNERS=$(docker trust inspect $IMAGE | jq -r '.[].SignedTags[].Signers[]')
    echo "Signed by: $SIGNERS"
    
    # Verify specific signer
    if echo "$SIGNERS" | grep -q "release-team"; then
        echo "✓ Signed by release team"
        exit 0
    else
        echo "✗ Not signed by release team"
        exit 1
    fi
else
    echo "✗ Image is not signed"
    exit 1
fi
EOF

chmod +x verify-image.sh

# Test verification
./verify-image.sh myregistry/myapp:1.0.0
```

### Section 2.4: Registry Security and Management (60 minutes)

#### Registry Types and Security Models

1. **Public Registries** (Docker Hub, Quay.io)
   - Convenient but trust challenges
   - Rate limiting considerations
   - Namespace squatting risks

2. **Private Registries**
   - Full control over access
   - Integration with corporate auth
   - Compliance and audit capabilities

3. **Air-Gapped Registries**
   - Maximum security
   - Manual update processes
   - Suitable for sensitive environments

#### Securing Your Registry

### Lab 2.4: Private Registry Implementation

**Exercise 1: Deploy Secure Private Registry**

```bash
cd ~/docker-security/module2/lab4

# Generate certificates for TLS
mkdir -p certs auth

# Create self-signed certificate (production: use real cert!)
openssl req -newkey rsa:4096 -nodes -keyout certs/registry.key \
  -x509 -days 365 -out certs/registry.crt \
  -subj "/C=US/ST=State/L=City/O=Company/CN=registry.local"

# Create htpasswd file for basic auth
docker run --rm --entrypoint htpasswd registry:2 \
  -Bbn admin secretpassword > auth/htpasswd

# Create registry configuration
cat > config.yml << 'EOF'
version: 0.1
log:
  level: info
  formatter: json
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
http:
  addr: :5000
  tls:
    certificate: /certs/registry.crt
    key: /certs/registry.key
auth:
  htpasswd:
    realm: Registry Realm
    path: /auth/htpasswd
middleware:
  registry:
    - name: vulnerabilityscanning
      options:
        enabled: true
    - name: ratelimiting
      options:
        requests: 100
        window: 1m
EOF

# Deploy secure registry
docker run -d \
  --name secure-registry \
  -p 5000:5000 \
  -v $(pwd)/config.yml:/etc/docker/registry/config.yml:ro \
  -v $(pwd)/certs:/certs:ro \
  -v $(pwd)/auth:/auth:ro \
  -v registry-data:/var/lib/registry \
  registry:2

# Configure Docker to trust the certificate
sudo mkdir -p /etc/docker/certs.d/registry.local:5000
sudo cp certs/registry.crt /etc/docker/certs.d/registry.local:5000/ca.crt

# Add registry.local to /etc/hosts
echo "127.0.0.1 registry.local" | sudo tee -a /etc/hosts

# Test authentication
docker login registry.local:5000 -u admin -p secretpassword

# Push test image
docker tag alpine:latest registry.local:5000/alpine:latest
docker push registry.local:5000/alpine:latest
```

**Exercise 2: Registry Security Policies**

```bash
# Implement admission webhooks
cat > admission-policy.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: registry-policies
data:
  policies.rego: |
    package docker.registry
    
    default allow = false
    
    # Only allow images from approved registries
    allow {
      input.image.registry == "registry.local:5000"
    }
    
    # Require image signing
    allow {
      input.image.signatures[_].verified == true
    }
    
    # Block latest tag in production
    deny[msg] {
      input.image.tag == "latest"
      input.environment == "production"
      msg := "Latest tag not allowed in production"
    }
    
    # Require vulnerability scanning
    deny[msg] {
      input.image.scan_status != "passed"
      msg := "Image must pass vulnerability scan"
    }
    
    # Age limit for base images
    deny[msg] {
      age_days := time.now_ns() - input.image.created
      age_days > 30 * 24 * 60 * 60 * 1000000000
      msg := "Base image is too old (>30 days)"
    }
EOF

# Create policy enforcement script
cat > enforce-policy.sh << 'EOF'
#!/bin/bash
IMAGE=$1
ENVIRONMENT=${2:-development}

# Extract image details
REGISTRY=$(echo $IMAGE | cut -d'/' -f1)
TAG=$(echo $IMAGE | cut -d':' -f2)

# Check policies
echo "Evaluating policies for $IMAGE in $ENVIRONMENT..."

# Check registry whitelist
ALLOWED_REGISTRIES="registry.local:5000 company.azurecr.io"
if ! echo $ALLOWED_REGISTRIES | grep -q $REGISTRY; then
    echo "✗ Registry $REGISTRY not in whitelist"
    exit 1
fi

# Check tag policy
if [ "$TAG" == "latest" ] && [ "$ENVIRONMENT" == "production" ]; then
    echo "✗ Latest tag not allowed in production"
    exit 1
fi

# Check image age
IMAGE_CREATED=$(docker inspect $IMAGE --format='{{.Created}}')
IMAGE_AGE_DAYS=$(( ($(date +%s) - $(date -d "$IMAGE_CREATED" +%s)) / 86400 ))
if [ $IMAGE_AGE_DAYS -gt 30 ]; then
    echo "✗ Image is $IMAGE_AGE_DAYS days old (max: 30)"
    exit 1
fi

echo "✓ All policies passed"
exit 0
EOF

chmod +x enforce-policy.sh
```

**Exercise 3: Registry Mirroring and Caching**

```bash
# Setup pull-through cache
cat > mirror-config.yml << 'EOF'
version: 0.1
proxy:
  remoteurl: https://registry-1.docker.io
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: :5001
  tls:
    certificate: /certs/registry.crt
    key: /certs/registry.key
EOF

# Deploy caching registry
docker run -d \
  --name registry-mirror \
  -p 5001:5001 \
  -v $(pwd)/mirror-config.yml:/etc/docker/registry/config.yml:ro \
  -v $(pwd)/certs:/certs:ro \
  -v mirror-data:/var/lib/registry \
  registry:2

# Configure Docker daemon to use mirror
cat > daemon-mirror.json << 'EOF'
{
  "registry-mirrors": ["https://registry.local:5001"],
  "insecure-registries": [],
  "debug": true
}
EOF

# Test mirror
docker pull alpine:latest  # First pull: from Docker Hub
docker rmi alpine:latest
docker pull alpine:latest  # Second pull: from local mirror (faster!)
```

### Section 2.5: Supply Chain Security and SBOM (30 minutes)

#### Software Bill of Materials (SBOM)

An SBOM is a complete inventory of all components in your container image, essential for:
- Vulnerability tracking
- License compliance
- Supply chain transparency
- Incident response

### Lab 2.5: SBOM Generation and Analysis

```bash
cd ~/docker-security/module2/lab5

# Install SBOM tools
# Syft for generation
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype for vulnerability matching
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM
syft alpine:latest -o json > alpine-sbom.json
syft alpine:latest -o spdx > alpine-sbom.spdx
syft alpine:latest -o cyclonedx > alpine-sbom.xml

# Analyze SBOM contents
echo "=== Package Summary ==="
jq '.artifacts | length' alpine-sbom.json
jq '.artifacts[] | select(.type=="apk") | .name' alpine-sbom.json | sort | uniq

# Create comprehensive SBOM analysis
cat > analyze-sbom.sh << 'EOF'
#!/bin/bash
IMAGE=$1
OUTPUT_DIR=${2:-sbom-reports}

mkdir -p $OUTPUT_DIR

echo "Generating SBOM for $IMAGE..."

# Generate multiple formats
syft $IMAGE -o json > $OUTPUT_DIR/sbom.json
syft $IMAGE -o spdx-json > $OUTPUT_DIR/sbom.spdx.json
syft $IMAGE -o cyclonedx-json > $OUTPUT_DIR/sbom.cyclonedx.json
syft $IMAGE -o table > $OUTPUT_DIR/sbom.txt

# Analyze components
echo "=== Component Analysis ==="
TOTAL_PACKAGES=$(jq '.artifacts | length' $OUTPUT_DIR/sbom.json)
echo "Total packages: $TOTAL_PACKAGES"

# Group by type
echo -e "\nPackages by type:"
jq -r '.artifacts | group_by(.type) | .[] | "\(.[0].type): \(length)"' $OUTPUT_DIR/sbom.json

# Find potentially risky packages
echo -e "\nPotentially risky packages:"
jq -r '.artifacts[] | select(.name | test("dev|debug|test")) | "\(.name) (\(.version))"' $OUTPUT_DIR/sbom.json

# Check for known vulnerable versions
grype sbom:$OUTPUT_DIR/sbom.json -o json > $OUTPUT_DIR/vulnerabilities.json

# License analysis
echo -e "\nLicense summary:"
jq -r '.artifacts[].licenses[]?.value' $OUTPUT_DIR/sbom.json | sort | uniq -c | sort -nr

echo "Reports generated in $OUTPUT_DIR/"
EOF

chmod +x analyze-sbom.sh

# Test with various images
./analyze-sbom.sh alpine:latest
./analyze-sbom.sh nginx:latest
./analyze-sbom.sh python:3.9
```

## Section 2.6: Module Assessment (30 minutes)

### Practical Project: Secure Image Pipeline

**Project Requirements:**
Build a complete secure image pipeline that:
1. Uses minimal base images
2. Implements multi-stage builds
3. Runs as non-root user
4. Includes vulnerability scanning
5. Signs images with DCT
6. Generates and stores SBOM
7. Enforces security policies

**Project Scaffold:**

```bash
# Create project structure
mkdir -p secure-pipeline/{src,scripts,policies,reports}
cd secure-pipeline

# Application source
cat > src/app.py << 'EOF'
from flask import Flask, jsonify
import os
import sys

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "version": os.getenv("APP_VERSION", "1.0.0"),
        "user": os.getenv("USER", "unknown"),
        "python": sys.version
    })

@app.route('/')
def index():
    return jsonify({
        "message": "Secure containerized application",
        "features": [
            "Minimal base image",
            "Non-root execution",
            "Vulnerability scanning",
            "Image signing",
            "SBOM generation"
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

cat > src/requirements.txt << 'EOF'
flask==2.3.2
gunicorn==20.1.0
EOF

# Secure Dockerfile
cat > Dockerfile << 'EOF'
# Build stage
FROM python:3.11-slim AS builder

WORKDIR /build
COPY src/requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Security scanning stage
FROM aquasec/trivy:latest AS scanner
COPY --from=builder /root/.local /scan
RUN trivy filesystem --exit-code 1 --severity HIGH,CRITICAL /scan

# Final stage
FROM python:3.11-slim

# Security updates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder --chown=appuser:appuser /root/.local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Copy application
COPY --chown=appuser:appuser src/app.py .

# Security hardening
RUN chmod -R 755 /app && \
    find /app -type f -exec chmod 644 {} \;

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

# Metadata
LABEL maintainer="security-team@example.com" \
      version="1.0.0" \
      security.scan="passed" \
      description="Secure Python Flask application"

ENV APP_VERSION=1.0.0

EXPOSE 5000

CMD ["python", "app.py"]
EOF

# Build script with security checks
cat > scripts/build-secure.sh << 'EOF'
#!/bin/bash
set -euo pipefail

IMAGE_NAME=${1:-secure-app}
VERSION=${2:-latest}
REGISTRY=${REGISTRY:-registry.local:5000}

echo "🔨 Building secure image: $REGISTRY/$IMAGE_NAME:$VERSION"

# Build image
docker build -t $REGISTRY/$IMAGE_NAME:$VERSION .

echo "🔍 Running security scans..."

# Vulnerability scan
trivy image --exit-code 0 --severity HIGH,CRITICAL $REGISTRY/$IMAGE_NAME:$VERSION

# Generate SBOM
echo "📋 Generating SBOM..."
syft $REGISTRY/$IMAGE_NAME:$VERSION -o json > reports/sbom-$VERSION.json
syft $REGISTRY/$IMAGE_NAME:$VERSION -o spdx > reports/sbom-$VERSION.spdx

# Policy checks
echo "📝 Checking security policies..."
docker run --rm -v $(pwd)/policies:/policies \
    -v /var/run/docker.sock:/var/run/docker.sock \
    openpolicyagent/opa eval \
    -d /policies/image-policies.rego \
    -i /policies/image-data.json \
    "data.docker.image.allow"

# Sign image
if [ "$DOCKER_CONTENT_TRUST" = "1" ]; then
    echo "✍️  Signing image..."
    docker trust sign $REGISTRY/$IMAGE_NAME:$VERSION
fi

# Push to registry
echo "📤 Pushing to registry..."
docker push $REGISTRY/$IMAGE_NAME:$VERSION

echo "✅ Build complete!"
echo "Image: $REGISTRY/$IMAGE_NAME:$VERSION"
echo "SBOM: reports/sbom-$VERSION.json"
EOF

chmod +x scripts/build-secure.sh

# Security policies
cat > policies/image-policies.rego << 'EOF'
package docker.image

default allow = false

# Image must not run as root
deny[msg] {
    input.Config.User == ""
    msg := "Container must not run as root"
}

deny[msg] {
    input.Config.User == "root"
    msg := "Container must not run as root"
}

# Must have health check
deny[msg] {
    not input.Config.Healthcheck
    msg := "Container must have health check"
}

# No sensitive environment variables
deny[msg] {
    input.Config.Env[_] == regex.match(".*PASSWORD.*", input.Config.Env[_])
    msg := "No passwords in environment variables"
}

# Must use specific base images
allowed_bases := [
    "python:3.11-slim",
    "alpine:3.17",
    "distroless/python3"
]

deny[msg] {
    not input.Config.Image in allowed_bases
    msg := sprintf("Base image must be one of: %v", [allowed_bases])
}

# All conditions must pass
allow {
    count(deny) == 0
}
EOF

# CI/CD Pipeline
cat > .gitlab-ci.yml << 'EOF'
stages:
  - build
  - scan
  - sign
  - deploy

variables:
  IMAGE_NAME: $CI_REGISTRY_IMAGE
  IMAGE_TAG: $CI_COMMIT_SHORT_SHA

build:
  stage: build
  script:
    - docker build -t $IMAGE_NAME:$IMAGE_TAG .
    - docker push $IMAGE_NAME:$IMAGE_TAG

security_scan:
  stage: scan
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity HIGH,CRITICAL $IMAGE_NAME:$IMAGE_TAG
    - trivy image --format template --template "@contrib/gitlab.tpl" -o gl-container-scanning-report.json $IMAGE_NAME:$IMAGE_TAG
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json

generate_sbom:
  stage: scan
  image: anchore/syft:latest
  script:
    - syft $IMAGE_NAME:$IMAGE_TAG -o spdx > sbom.spdx
    - syft $IMAGE_NAME:$IMAGE_TAG -o json > sbom.json
  artifacts:
    paths:
      - sbom.spdx
      - sbom.json
    expire_in: 1 year

sign_image:
  stage: sign
  script:
    - export DOCKER_CONTENT_TRUST=1
    - docker trust sign $IMAGE_NAME:$IMAGE_TAG
  only:
    - main

deploy:
  stage: deploy
  script:
    - export DOCKER_CONTENT_TRUST=1
    - docker pull $IMAGE_NAME:$IMAGE_TAG
    - kubectl set image deployment/app app=$IMAGE_NAME:$IMAGE_TAG
  only:
    - main
EOF

# Test the complete pipeline
./scripts/build-secure.sh secure-app 1.0.0
```

### Knowledge Assessment Quiz

1. **What is the primary security benefit of using Alpine Linux as a base image?**
   - a) It's faster to download
   - b) Minimal attack surface with fewer packages ✓
   - c) Better performance
   - d) Easier to configure

2. **Which Dockerfile instruction should you use to avoid storing secrets in image layers?**
   - a) ENV
   - b) ARG
   - c) RUN --mount=type=secret ✓
   - d) COPY --secret

3. **What does Docker Content Trust (DCT) provide?**
   - a) Encryption of image contents
   - b) Image signing and verification ✓
   - c) Access control to registries
   - d) Vulnerability scanning

4. **When using multi-stage builds, what is copied to the final stage?**
   - a) The entire build context
   - b) All layers from previous stages
   - c) Only explicitly copied artifacts ✓
   - d) Source code and dependencies

5. **What is an SBOM?**
   - a) Security Benchmark Operations Manual
   - b) Software Bill of Materials ✓
   - c) System Binary Object Model
   - d) Secure Build Operations Module

6. **Which command drops all capabilities except NET_BIND_SERVICE?**
   - a) --cap-drop=ALL --cap-add=NET_BIND_SERVICE ✓
   - b) --cap-add=NONE --cap-keep=NET_BIND_SERVICE
   - c) --capabilities=NET_BIND_SERVICE
   - d) --security-opt cap=NET_BIND_SERVICE

7. **What is the recommended way to handle image updates?**
   - a) Use latest tag for automatic updates
   - b) Pin specific versions and scan before updating ✓
   - c) Rebuild images daily
   - d) Never update base images

8. **Which tool generates SBOMs in multiple formats?**
   - a) Trivy
   - b) Clair
   - c) Syft ✓
   - d) Docker scan

### Practical Exercises

**Exercise 1: Fix the Vulnerable Dockerfile**

Given this vulnerable Dockerfile, identify and fix all security issues:

```dockerfile
# VULNERABLE VERSION - DO NOT USE
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl wget netcat
ENV API_KEY=sk_live_abcd1234
COPY . /app
WORKDIR /app
RUN chmod 777 -R /app
EXPOSE 22 80 443 3306 5432 6379 8080 9090
CMD ["python", "app.py"]
```

**Exercise 2: Implement Automated Security Pipeline**

Create a GitHub Actions workflow that:
1. Builds a container image
2. Scans for vulnerabilities
3. Generates an SBOM
4. Signs the image
5. Only deploys if all security checks pass

## Module Summary

### Key Takeaways

1. **Secure Image Building**
   - Always use minimal base images
   - Implement multi-stage builds
   - Never run as root
   - Don't store secrets in layers

2. **Vulnerability Management**
   - Scan at build time AND runtime
   - Fix vulnerabilities promptly
   - Use multiple scanning tools
   - Track dependencies with SBOMs

3. **Trust and Verification**
   - Enable Docker Content Trust
   - Sign all production images
   - Verify signatures before deployment
   - Maintain secure key management

4. **Registry Security**
   - Use private registries for sensitive images
   - Implement strong authentication
   - Enable vulnerability scanning
   - Monitor for unusual activity

5. **Supply Chain Security**
   - Generate SBOMs for all images
   - Track component licenses
   - Monitor for supply chain attacks
   - Implement security policies

### Command Cheat Sheet

```bash
# Scanning Commands
trivy image <image>
grype <image>
docker scan <image>
snyk container test <image>

# SBOM Generation
syft <image> -o json
syft <image> -o spdx
grype sbom:./sbom.json

# Docker Content Trust
export DOCKER_CONTENT_TRUST=1
docker trust key generate <name>
docker trust signer add --key <key> <name> <repository>
docker trust sign <image>
docker trust inspect <image>

# Registry Operations
docker login <registry>
docker tag <image> <registry>/<image>
docker push <registry>/<image>
docker pull <registry>/<image>

# Security Best Practices
docker run --user 1000:1000 <image>
docker run --read-only <image>
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE <image>
docker run --security-opt no-new-privileges <image>
```

### Next Module Preview

In Module 3: Runtime Security and Container Hardening, we'll explore:
- Advanced security profiles (AppArmor, SELinux, seccomp)
- Runtime threat detection
- Container forensics
- Incident response procedures

### Additional Resources

1. **Documentation**
   - [Docker Official Docs - Security](https://docs.docker.com/engine/security/)
   - [OCI Image Specification](https://github.com/opencontainers/image-spec)
   - [The Update Framework](https://theupdateframework.io/)

2. **Tools**
   - [Trivy](https://github.com/aquasecurity/trivy)
   - [Syft](https://github.com/anchore/syft)
   - [Cosign](https://github.com/sigstore/cosign)
   - [Notary](https://github.com/notaryproject/notary)

3. **Best Practices**
   - [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
   - [NIST SP 800-190](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
   - [OWASP Container Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)