# Difference between **Seccomp** and **AppArmor/SELinux**

The key difference between **Seccomp** and **AppArmor/SELinux** lies in **what they restrict** and **how they enforce security** in Linux systems:

---

## 🔐 Seccomp vs AppArmor vs SELinux

| Feature               | **Seccomp**                             | **AppArmor**                                  | **SELinux**                                        |
| --------------------- | --------------------------------------- | --------------------------------------------- | -------------------------------------------------- |
| **Scope**             | Filters system calls                    | Applies to file paths (programs + resources)  | Applies to all system objects (MAC, Type-Enforced) |
| **Granularity**       | Per system call (fine-grained)          | Per path and program profile                  | Per label and domain/type                          |
| **Mechanism**         | Uses BPF filters to allow/deny syscalls | Uses per-program profiles                     | Uses security labels and policies                  |
| **Complexity**        | Medium (requires syscall knowledge)     | Low to Medium (easier to write profiles)      | High (complex policy language and management)      |
| **Default in Docker** | Yes (default seccomp profile applied)   | Supported (needs to be explicitly configured) | Supported (often disabled by default)              |
| **Policy Format**     | JSON-based filters                      | Text profiles (e.g., `/etc/apparmor.d/`)      | Binary policies from `.te` or `.cil` sources       |
| **Enforcement**       | Whitelist-based syscall restriction     | Path-based access control                     | Label-based mandatory access control (MAC)         |
| **Target**            | Kernel syscall interface                | Files, network, capabilities, signals         | Everything: files, processes, network, sockets     |
| **Compatibility**     | Linux only (limited portability)        | Linux only                                    | Linux only                                         |

---

## 🧠 In Simple Terms

* **Seccomp**:
  Blocks dangerous system calls like `ptrace`, `clone`, `mount`, etc.
  Think of it as **"deny the ability to ask the kernel certain questions"**.

* **AppArmor**:
  Restricts what a specific executable (e.g., `/usr/bin/nginx`) can read/write/access based on its path.
  Think of it as **"this program can touch only these paths/files"**.

* **SELinux**:
  Applies a label to **everything** and enforces very detailed rules.
  Think of it as **"a program with label X can access object with label Y only under rule Z"**.

---

## 🧪 Example Use Case in Containers

| Feature      | Example                                                                                                         |
| ------------ | --------------------------------------------------------------------------------------------------------------- |
| **Seccomp**  | Prevent containers from calling `mount`, `unshare`, `reboot`, etc.                                              |
| **AppArmor** | Limit containerized NGINX to serve only files from `/srv/www`                                                   |
| **SELinux**  | Ensure container process with label `svirt_lxc_net_t` can write only to files with label `svirt_sandbox_file_t` |

---

### 🧰 Use Together for Defense in Depth

They are **not mutually exclusive**. Many hardened systems (including container runtimes) use:

* **Seccomp** → restrict syscall attack surface
* **AppArmor** or **SELinux** → control resource access
* **Capabilities** → drop Linux privileges


