# Lab: Seccomp and AppArmor Profiles (Ubuntu 24.04 Guide)

## Objective
Apply and test security profiles to restrict container behavior at runtime using Seccomp and AppArmor on Ubuntu 24.04.

## Prerequisites
- Ubuntu 24.04 system (VM or bare metal)
- Docker Engine installed (`sudo apt update && sudo apt install docker.io -y`)
- AppArmor enabled (default on Ubuntu)

## Lab Steps

1. **Start a Container with Default Profiles**
   - Example: Run an Ubuntu container interactively:
     ```bash
     docker run --rm -it ubuntu:24.04 bash
     ```
   - By default, Docker applies its default seccomp and AppArmor profiles.

2. **Attempt Restricted Actions**
   - Try mounting a filesystem (should be blocked by seccomp):
     ```bash
     mount -t tmpfs none /mnt
     ```
   - Try changing kernel parameters (should be blocked):
     ```bash
     sysctl -w kernel.shmmax=17179869184
     ```
   - Observe error messages indicating permission denied or operation not permitted.

3. **Observe and Document Results**
   - Note which actions are blocked and the error messages received.
   - Example: `mount: permission denied (are you root?)` or `Operation not permitted`.

4. **Create a Custom Seccomp Profile**
   - Save the following as `custom-seccomp.json`:
     ```json
     {
       "defaultAction": "SCMP_ACT_ERRNO",
       "syscalls": [
         {"names": ["execve", "exit", "read", "write"], "action": "SCMP_ACT_ALLOW"}
       ]
     }
     ```
   - This profile only allows basic syscalls and blocks most others.

5. **Run a Container with the Custom Seccomp Profile**
   ```bash
   docker run --rm -it --security-opt seccomp=./custom-seccomp.json ubuntu:24.04 bash
   ```
   - Try running commands like `ls`, `cat`, and observe which ones work or fail.

6. **Apply a Custom AppArmor Profile (Advanced)**
   - Create a simple AppArmor profile (e.g., `my-docker-profile`) and load it:
     ```bash
     sudo aa-genprof /usr/bin/docker
     # Follow prompts to create and enforce the profile
     ```
   - Run a container with your profile:
     ```bash
     docker run --rm -it --security-opt apparmor=my-docker-profile ubuntu:24.04 bash
     ```

## Deliverable
Submit your custom seccomp profile, any AppArmor profile used, and a summary of the restrictions enforced and observed during the lab.
