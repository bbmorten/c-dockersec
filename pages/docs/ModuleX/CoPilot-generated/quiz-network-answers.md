# Answers: Network Security Quiz

1. **What is the difference between bridge and host networking in Docker?**
   - Bridge networking isolates containers on a private network, while host networking shares the host's network stack with the container.
2. **How can you restrict container-to-container communication?**
   - By using custom Docker networks, network policies, or firewalls to control traffic between containers.
3. **True or False: All containers on the same Docker network can communicate by default.**
   - True. By default, containers on the same network can communicate unless restricted.
4. **What is a network policy and how is it enforced?**
   - A network policy defines allowed/denied traffic between containers, enforced by Docker or orchestration tools like Kubernetes.
5. **Name one tool for monitoring network traffic in Docker environments.**
   - Wireshark, tcpdump, or Cilium.
