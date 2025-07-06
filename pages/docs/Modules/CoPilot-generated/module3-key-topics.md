# Module 3 Key Topics: Runtime Security and Hardening

## User Namespaces and Capabilities
- Limit container privileges using user namespaces.
- Drop unnecessary Linux capabilities to reduce risk.

**Diagram: User Namespace Isolation**

```
[Host UID 1000] <-> [Container UID 0 (root)]
```

**References:**
- [Docker Docs: Use user namespaces](https://docs.docker.com/engine/security/userns-remap/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

## Seccomp, AppArmor, and SELinux
- Apply seccomp profiles to restrict system calls.
- Use AppArmor or SELinux to enforce mandatory access controls.
- Customize profiles for specific workloads.

**Diagram: Security Profile Enforcement**

```
[Container Process] --(seccomp/AppArmor/SELinux)--> [Allowed/Blocked Action]
```

**References:**
- [Docker Docs: Seccomp security profiles](https://docs.docker.com/engine/security/seccomp/)
- [AppArmor Documentation](https://wiki.ubuntu.com/AppArmor)
- [SELinux Project](https://selinuxproject.org/)

## Resource Limits and Isolation
- Set CPU, memory, and disk quotas to prevent resource abuse.
- Use cgroups and namespaces for process isolation.

**Diagram: Resource Limiting**

```
[Container] --(cgroups)--> [CPU/Memory Quota]
```

**References:**
- [Docker Docs: Limit a container's resources](https://docs.docker.com/config/containers/resource_constraints/)
- [Linux cgroups](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)

## Runtime Monitoring Tools
- Deploy Falco or Sysdig to monitor container activity.
- Detect suspicious behavior and respond to incidents.

**Diagram: Runtime Monitoring**

```
[Container] --> [Falco/Sysdig] --> [Alert/Event]
```

**References:**
- [Falco Project](https://falco.org/)
- [Sysdig Open Source](https://sysdig.com/opensource/)

## Responding to Suspicious Behavior
- Investigate alerts, collect evidence, and take containment actions.
- Document incidents and update security policies.

**References:**
- [NIST: Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [Docker Docs: Security best practices](https://docs.docker.com/engine/security/security/)

## Docker Engine: Root vs. Rootless Mode
- **Root Mode:** By default, Docker Engine runs as root, and containers also run as root inside their namespaces. This means a container escape can lead to full host compromise.
- **Rootless Mode:** Docker can run as a non-root user, reducing the risk of privilege escalation. In rootless mode, containers cannot access host resources that require root, and their capabilities are further restricted.

**Diagram: Root vs. Rootless**

```text
[Host OS]
  |--[Docker Engine (root)]----[Container (root)]
  |--[Docker Engine (user)]----[Container (user)]
```

**References:**
- [Docker Docs: Rootless mode](https://docs.docker.com/engine/security/rootless/)

## Docker Using containerd Engine
- Docker uses containerd as its container runtime. Docker manages images, networking, and orchestration, while containerd handles the low-level container lifecycle (create, start, stop).
- Security policies (seccomp, AppArmor, user namespaces) are still managed by Docker, but actual container processes are spawned by containerd.

**Diagram: Docker and containerd**

```text
[Docker CLI] -> [Docker Daemon] -> [containerd] -> [runc] -> [Container]
```

**References:**
- [Docker Docs: containerd](https://docs.docker.com/engine/containerd/)
- [containerd Project](https://containerd.io/)

## Standalone containerd Engine
- containerd can be used directly (without Docker) to manage containers. This is common in Kubernetes environments.
- Security is managed via containerd configuration and plugins. Policies like seccomp and AppArmor can be applied, but orchestration and image management are handled externally (e.g., by Kubernetes).

**Diagram: Standalone containerd**

```text
[containerd] -> [runc] -> [Container]
```

**References:**
- [containerd Documentation](https://containerd.io/docs/)

## gVisor
- gVisor is a user-space kernel that intercepts container syscalls, providing an extra layer of isolation between containers and the host kernel.
- It can be used as a runtime with Docker or Kubernetes, reducing the risk of kernel exploits.

**Diagram: gVisor Architecture**

```text
[Container] -> [gVisor Sentry] -> [Host Kernel]
```

**References:**
- [gVisor Project](https://gvisor.dev/)
- [Google Blog: Introducing gVisor](https://cloud.google.com/blog/products/containers-kubernetes/introducing-gvisor-container-native-sandbox)

## Kata Containers
- Kata Containers provide lightweight virtual machines for each container, combining VM-level isolation with container speed.
- Each container runs inside its own microVM, using a minimal kernel and hypervisor.

**Diagram: Kata Containers**

```text
[Container] -> [Kata Shim] -> [QEMU/KVM] -> [MicroVM] -> [Host Kernel]
```

**References:**
- [Kata Containers Project](https://katacontainers.io/)
- [Kata Containers Architecture](https://katacontainers.io/docs/architecture/)
