# Module 1 Key Topics: Introduction to Docker Security

## Containers vs. Virtual Machines
- Understand the differences in architecture, isolation, and security boundaries.
- Learn why containers share the host kernel and the implications for security.

**Diagram: Container vs. VM**

```
+-------------------+      +-------------------+
|   Host Hardware   |      |   Host Hardware   |
+-------------------+      +-------------------+
|   Host OS Kernel  |      |   Host OS Kernel  |
+-------------------+      +-------------------+
|   Docker Engine   |      | Hypervisor        |
+-------------------+      +-------------------+
| Container | Cont. |      | VM 1 | VM 2 | ... |
|   App    |  App  |      | OS   | OS   |     |
+-------------------+      +-------------------+
```

**References:**
- [Docker Docs: What is a Container?](https://docs.docker.com/get-started/overview/)
- [Red Hat: Containers vs. VMs](https://www.redhat.com/en/topics/containers/containers-vs-vms)

## Docker Architecture and Attack Surfaces
- Explore Docker components: daemon, client, images, containers, and registry.
- Identify attack surfaces such as the Docker socket, image sources, and container runtime.

**Diagram: Docker Architecture**

```
+-------------------+
|   Docker Client   |
+-------------------+
         |
         v
+-------------------+
|  Docker Daemon    |
+-------------------+
   |    |      |
   v    v      v
Images Containers Registry
```

**References:**
- [Docker Docs: Docker Architecture](https://docs.docker.com/engine/docker-overview/)
- [OWASP: Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

## Real-World Container Security Breaches
- Analyze notable incidents (e.g., Tesla Kubernetes breach) and what went wrong.
- Discuss lessons learned and how to avoid similar mistakes.

**Reference:**
- [Tesla Kubernetes Breach](https://www.redlock.io/blog/cryptojacking-tesla)
- [CNCF: Container Security Incidents](https://www.cncf.io/blog/2020/02/11/container-security-incident-response/)

## Shared Kernel Model
- Examine how containers use the host kernel and the risks of kernel vulnerabilities.
- Understand the importance of kernel patching and minimizing host attack surface.

**Diagram: Shared Kernel**

```
+-------------------+
|   Host Kernel     |
+-------------------+
| Cont. | Cont. |   |
| App   | App   |   |
+-------------------+
```

**Reference:**
- [Linux Kernel Security](https://www.kernel.org/doc/html/latest/admin-guide/security.html)

## Container Threat Landscape
- Overview of supply chain, runtime, and network threats.
- Introduction to threat modeling for containerized environments.

**Reference:**
- [NIST Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [Microsoft: Container Threat Modeling](https://techcommunity.microsoft.com/t5/azure-architecture-blog/container-threat-modeling/ba-p/344040)
