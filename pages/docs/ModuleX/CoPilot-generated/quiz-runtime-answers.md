# Answers: Runtime Security Quiz

1. **What is the purpose of seccomp in Docker?**
   - Seccomp restricts the system calls a container can make, reducing the risk of kernel-level attacks.
2. **How does AppArmor help secure containers?**
   - AppArmor enforces security profiles that limit what resources a container can access on the host.
3. **True or False: Containers run as root by default unless specified otherwise.**
   - True. Unless a user is specified, containers run as root, which can be a security risk.
4. **What is a Linux capability and how can it be restricted in Docker?**
   - Linux capabilities are fine-grained permissions for processes. Docker allows dropping or adding capabilities using the `--cap-drop` and `--cap-add` flags.
5. **Name one tool for monitoring container runtime behavior.**
   - Falco, Sysdig, or Docker's built-in events/logs.
