# Answers: Image Security Quiz

1. **What is the benefit of using a minimal base image?**
   - Reduces the attack surface and potential vulnerabilities by including only necessary components.
2. **Name two tools for scanning Docker images for vulnerabilities.**
   - Trivy, Snyk, Clair, or Anchore.
3. **True or False: It is safe to use images from untrusted sources if you scan them first.**
   - False. Scanning helps, but untrusted images may contain hidden or zero-day threats.
4. **What is multi-stage build in Docker and how does it improve security?**
   - Multi-stage builds allow you to separate build and runtime environments, reducing the final image size and removing build tools or secrets from production images.
5. **How can you verify the authenticity of a Docker image?**
   - By checking its digital signature or using Docker Content Trust/Notary.
