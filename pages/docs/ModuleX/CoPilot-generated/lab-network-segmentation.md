# Lab: Network Segmentation (Ubuntu 24.04 Guide)

## Objective
Implement and test network segmentation for Docker containers on Ubuntu 24.04.

## Prerequisites
- Ubuntu 24.04 system (VM or bare metal)
- Docker Engine installed (`sudo apt update && sudo apt install docker.io -y`)

## Lab Steps

1. **Create Two Docker Networks**
   ```bash
   docker network create frontend
   docker network create backend
   ```

2. **Deploy Containers to Each Network**
   - Start a web server on the frontend network:
     ```bash
     docker run -d --name web --network frontend nginx:alpine
     ```
   - Start a database on the backend network:
     ```bash
     docker run -d --name db --network backend mongo:7
     ```
   - Start a test container connected to both networks:
     ```bash
     docker run -it --name tester --network frontend --rm alpine sh
     # In another terminal:
     docker network connect backend tester
     ```

3. **Verify Connectivity**
   - From the `tester` container, test connectivity:
     ```sh
     ping web
     ping db
     ```
   - By default, `tester` can reach both `web` and `db`, but `web` and `db` cannot reach each other.

4. **Apply Network Policies or Firewall Rules**
   - Docker does not natively support network policies, but you can use `iptables` to restrict traffic.
   - Example: Block tester from accessing db's port 27017:
     ```bash
     sudo iptables -I DOCKER-USER -s <tester_ip> -d <db_ip> -p tcp --dport 27017 -j DROP
     ```
   - Find container IPs with:
     ```bash
     docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' tester
     docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' db
     ```

5. **Test and Document Results**
   - Try to connect to the database from `tester` after applying the rule:
     ```sh
     nc -zv db 27017
     ```
   - Document which connections succeed or fail.

## Deliverable
Submit your network configuration, any firewall rules used, and a summary of your findings on container connectivity and segmentation.
