# Module 6 Key Topics: CI/CD Security and Compliance

## Secure Build and Deployment Pipelines
- Use GitHub Actions, GitLab CI, or Jenkins for automated builds.
- Restrict pipeline permissions and use least privilege.

**Diagram: CI/CD Pipeline**

```
[Source Code] -> [CI/CD Pipeline] -> [Build] -> [Scan] -> [Deploy]
```

**References:**
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitLab CI/CD Pipelines](https://docs.gitlab.com/ee/ci/)
- [Jenkins Pipeline](https://www.jenkins.io/doc/book/pipeline/)

## Automated Security Testing
- Integrate Trivy, Snyk, or other scanners into the pipeline.
- Fail builds on critical vulnerabilities.

**Diagram: Security Scan in Pipeline**

```
[Build Image] -> [Trivy/Snyk] -> [Vulnerability Report]
```

**References:**
- [Trivy GitHub Action](https://github.com/aquasecurity/trivy-action)
- [Snyk CI/CD Integration](https://snyk.io/docs/integrations/ci-cd/)

## Compliance Frameworks
- Apply CIS Docker Benchmark, NIST, or PCI DSS controls.
- Document compliance status and automate checks.

**References:**
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

## Policy Enforcement and Compliance Gates
- Enforce security policies as code in the pipeline.
- Block deployments that fail security or compliance checks.

**Diagram: Policy Gate**

```
[Pipeline] -> [Policy Check] --(pass)--> [Deploy]
                        |--(fail)--> [Block]
```

**References:**
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [OPA Gatekeeper for Kubernetes](https://github.com/open-policy-agent/gatekeeper)

## Supply Chain Security
- Track image provenance and use signed images.
- Monitor dependencies for vulnerabilities and license issues.

**References:**
- [SLSA: Supply Chain Levels for Software Artifacts](https://slsa.dev/)
- [Docker Docs: Content Trust](https://docs.docker.com/engine/security/trust/)
