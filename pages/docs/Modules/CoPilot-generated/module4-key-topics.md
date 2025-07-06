# Module 4 Key Topics: Network Security for Containers

## Docker Networking Modes
- Understand bridge, host, overlay, and macvlan modes.
- Choose the right mode for your security and connectivity needs.

**Diagram: Docker Networking Modes**

```
[Host]--(bridge)--[Container1]
      |--(host)----[Container2]
      |--(overlay)-[Container3]
      |--(macvlan)-[Container4]
```

**References:**
- [Docker Docs: Networking overview](https://docs.docker.com/network/)
- [Docker Networking Modes Explained](https://www.digitalocean.com/community/tutorials/how-to-use-docker-networking)

## Network Segmentation and Isolation
- Use custom Docker networks to isolate workloads.
- Prevent lateral movement between containers.

**Diagram: Network Segmentation**

```
[frontend] <--> [web] <--> [backend] <--> [db]
```

**References:**
- [Docker Docs: Network isolation](https://docs.docker.com/network/)
- [OWASP: Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#networking)

## Firewalls and Network Policies
- Apply iptables rules or use Cilium for fine-grained control.
- Enforce allow/deny rules for container traffic.

**Diagram: Firewall Rule**

```
[Container1] --X--> [Container2] (blocked by iptables)
```

**References:**
- [Docker Docs: Control traffic with iptables](https://docs.docker.com/network/iptables/)
- [Cilium Project](https://cilium.io/)

## TLS Encryption
- Secure container communication with TLS.
- Manage certificates and keys securely.

**Diagram: TLS Communication**

```
[ContainerA] --(TLS)--> [ContainerB]
```

**References:**
- [Docker Docs: Protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/)
- [Let's Encrypt](https://letsencrypt.org/)

## Secrets Management for Network Credentials
- Store and distribute network credentials securely.
- Use Docker secrets or external vaults.

**References:**
- [Docker Docs: Manage sensitive data with Docker secrets](https://docs.docker.com/engine/swarm/secrets/)
- [HashiCorp Vault](https://www.vaultproject.io/)
