# 🧠 Lesson 13: High Availability and Redundancy with Bridges

## 🎯 Learning Objectives

By the end of this lesson, you will be able to:

- Understand methods to add redundancy to Linux bridge networks
- Configure bonding with bridges for link failover
- Use STP and teaming techniques for high availability

---

## 🛡️ Why Redundancy Matters

High Availability (HA) in network bridging ensures:

- No single point of failure
- Minimal disruption on NIC or cable failure
- Continuous connectivity in virtualized or containerized workloads

---

## 🔁 Option 1: Bridge + Bonding

Combine multiple NICs into a bonded interface and bridge over it.

### Step-by-Step: Active-Backup Bonding with Bridge

```bash
# Load bonding module
sudo modprobe bonding

# Create bonded interface
sudo ip link add bond0 type bond
sudo ip link set bond0 up
sudo ip link set eth0 down
sudo ip link set eth1 down
sudo ip link set eth0 master bond0
sudo ip link set eth1 master bond0

# Set bonding mode
echo 1 | sudo tee /sys/class/net/bond0/bonding/mode  # mode 1 = active-backup

# Create bridge
sudo ip link add br0 type bridge
sudo ip link set bond0 master br0
sudo ip link set br0 up
```

---

## 🧪 Hands-on Lab: HA with Bonded NICs

### Scenario: Two NICs, one bridge

```bash
# Install prerequisites
sudo apt install ifenslave

# Follow bonding + bridge setup above

# Test with:
ip addr show bond0
bridge link
cat /proc/net/bonding/bond0
```

Disconnect one cable and watch the failover in `/proc/net/bonding/bond0`.

---

## 🔄 Option 2: Teamd (Alternative to Bonding)

```bash
sudo apt install ifupdown2

# Create teamd config (JSON)
cat <<EOF | sudo tee /etc/teamd/teamd.conf
{
  "device": "team0",
  "runner": {"name": "activebackup"},
  "link_watch": {"name": "ethtool"},
  "ports": {
    "eth0": {},
    "eth1": {}
  }
}
EOF

# Start teamd
tsudo teamd -g -f /etc/teamd/teamd.conf
```

Then add `team0` to your bridge as usual.

---

## 🌲 Option 3: Redundancy via STP

Enable STP on all bridges and connect them with redundant links (e.g. veth or physical). STP will automatically block loops and activate backup paths.

---

## 🖼️ Diagram: Bridge + Bonded NICs

```
[ eth0 ]   [ eth1 ]
    |         |
  (bond0: active-backup)
          |
        [ br0 ]
```

---

## ❓ Review Questions

1. What bonding mode provides failover?
2. How do you check bonding interface status?
3. What command creates a bridge over a bonded interface?

### ✅ Answers

1. Mode 1 (active-backup)
2. `cat /proc/net/bonding/bond0`
3. `ip link set bond0 master br0`

---

## 🧯 Troubleshooting Tips

| Symptom | Cause | Fix |
|--------|--------|-----|
| Failover not working | Wrong bonding mode | Use `mode 1` for failover |
| No traffic on bridge | Bond interface not active | Ensure one slave is active |
| Bridge missing link | Interface not added to bridge | Use `bridge link` to verify |

---

## 🌐 Real-World Example

In data centers and critical labs, bridges are often created over bonded interfaces to allow transparent failover. This is especially important when multiple VMs or containers share a bridge with limited physical uplinks.

---

Next up: **Lesson 14 – Bridges in Software Defined Networking (SDN)** 🧠
