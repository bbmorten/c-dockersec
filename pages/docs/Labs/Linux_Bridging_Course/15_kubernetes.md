# 🧠 Lesson 15: Bridge Use in Kubernetes and Cloud-Native Networking

## 🎯 Learning Objectives

By the end of this lesson, you will be able to:

- Understand how bridges are used in Kubernetes networking
- Explore bridge usage with container runtimes like Docker and Podman
- Identify bridge-related CNI plugins and cloud-native use cases

---

## ☸️ How Kubernetes Uses Bridges

Kubernetes relies on **Container Network Interface (CNI)** plugins for pod networking.

The most basic plugin is the **`bridge` plugin**, which:

- Creates a Linux bridge (e.g., `cni0`)
- Connects each pod via a veth pair
- Assigns an IP from a pre-defined subnet

This results in all pods on the same node being in the same broadcast domain.

---

## 🐳 Docker and Podman

### Docker

Docker creates its own bridge (`docker0`) for container communication.

```bash
# Inspect Docker bridge
docker network inspect bridge
```

You can also create custom bridge networks with:

```bash
docker network create --driver bridge mycustombr
```

### Podman

Uses **CNI plugins** by default, similar to Kubernetes:

```bash
podman network ls
podman network inspect podman
```

---

## 🔧 Bridge CNI Plugin Config (Example)

```json
{
  "cniVersion": "0.4.0",
  "name": "mynet",
  "type": "bridge",
  "bridge": "cni0",
  "isGateway": true,
  "ipMasq": true,
  "ipam": {
    "type": "host-local",
    "subnet": "10.22.0.0/16",
    "routes": [{ "dst": "0.0.0.0/0" }]
  }
}
```

> File location: `/etc/cni/net.d/10-mynet.conf`

---

## 🧪 Hands-on Lab: Test Bridge-Based CNI

### Step 1: Install `containernetworking-plugins`

```bash
sudo apt install containernetworking-plugins
```

### Step 2: Use `bridge` plugin manually (optional advanced test)

- Set up namespace, veth pair, and use the plugin to connect them to a bridge

For real-world cases, most users rely on:

- Minikube (CNI `bridge` plugin by default)
- Kind (Kubernetes in Docker)

---

## 🖼️ Kubernetes Bridge Topology

```
[pod-a]   [pod-b]
   |         |
[veth0]   [veth1]
   |         |
      [ cni0 (Linux Bridge) ]
               |
          [eth0: host uplink]
```

---

## ❓ Review Questions

1. What CNI plugin provides basic bridge networking?
2. How does a pod connect to a Linux bridge?
3. What is Docker’s default bridge interface?

### ✅ Answers

1. `bridge`
2. Via a veth pair created by the CNI plugin
3. `docker0`

---

## 🧯 Troubleshooting Tips

| Symptom | Cause | Fix |
|--------|--------|-----|
| Pod can’t access host | IP routing or MASQ missing | Enable `isGateway` and `ipMasq` |
| Containers unreachable | veth not linked to bridge | Verify with `ip link` and `bridge link` |
| Custom bridge not working | IPAM misconfigured | Check CNI config in `/etc/cni/net.d/` |

---

## 🌐 Real-World Example

In single-node clusters or edge setups using Minikube, the bridge CNI plugin allows full Kubernetes networking without needing complex SDN setups — ideal for demos and CI pipelines.

---

🎓 Congratulations — you've reached the end of the core Linux Bridging Masterclass!

Next up: **Bonus Sections – Lab Setup Guide, Command Cheat Sheet, and Advanced Namespace Labs** 🧩
