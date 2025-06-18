# Answers: Docker Security Fundamentals Quiz

1. **What is the main difference between a container and a virtual machine?**
   - Containers share the host OS kernel and isolate applications at the process level, while virtual machines emulate hardware and run separate OS instances.
2. **Name two common attack surfaces in a Docker environment.**
   - Exposed container ports, vulnerable images, Docker socket, weak credentials, or misconfigured volumes.
3. **True or False: Containers always provide strong isolation from the host.**
   - False. Containers provide process isolation but share the host kernel, so kernel vulnerabilities can break isolation.
4. **What is the purpose of a Docker image signature?**
   - To verify the authenticity and integrity of an image, ensuring it has not been tampered with.
5. **List one real-world example of a container security breach and its cause.**
   - Example: Tesla's Kubernetes cluster was compromised due to an exposed dashboard, leading to cryptojacking attacks.
