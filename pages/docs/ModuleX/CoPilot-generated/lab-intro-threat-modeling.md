# Lab: Threat Modeling Docker Environments (Ubuntu 24.04 Guide)

## Objective

Identify and document potential threats in a sample Dockerized application environment using practical tools and analysis on Ubuntu 24.04.

## Prerequisites

- Ubuntu 24.04 system (VM or bare metal)
- Docker Engine installed (`sudo apt update && sudo apt install docker.io -y`)
- Docker Compose installed (`sudo apt install docker-compose-plugin -y`)
- User added to the `docker` group (`sudo usermod -aG docker $USER` and re-login)

## Lab Setup

1. **Clone the Sample Application**

   ```bash
   git clone https://github.com/docker/awesome-compose.git
   cd awesome-compose/react-express-mongodb
   ```

2. **Review the Docker Compose File**
   - Open `docker-compose.yaml` in your editor:

     ```bash
     nano docker-compose.yaml
     ```

   - Identify all services, ports, and volumes defined.
3. **Start the Application**

   ```bash
   docker compose up -d
   ```

4. **List Running Containers**

   ```bash
   docker ps
   ```

## Threat Modeling Steps

1. **Identify Attack Vectors (with Examples)**
   - **Exposed Ports:**
     - Example: In `docker-compose.yaml`, you see `ports: - "27017:27017"` for MongoDB. This exposes the database to the network.
     - Command:
       ```bash
       docker ps --format "table {{.Names}}\t{{.Ports}}"
       ```
   - **Default/Weak Credentials:**
     - Example: In `docker-compose.yaml`, you find `MONGO_INITDB_ROOT_USERNAME: root` and `MONGO_INITDB_ROOT_PASSWORD: example`.
     - Command:
       ```bash
       grep -i password docker-compose.yaml
       ```
   - **Untrusted/Outdated Images:**
     - Example: The image `mongo:4.2` is used, which may be outdated.
     - Command:
       ```bash
       docker images
       docker run --rm aquasec/trivy:latest image mongo:4.2
       ```
   - **Services Running as Root:**
     - Example: No `user:` field in the service definition means the container runs as root by default.
     - Command:
       ```bash
       docker exec -it <container_id> whoami
       ```

2. **Analyze Network Exposure (with Examples)**
   - **Host Ports:**
     - Command:
       ```bash
       ss -tuln | grep 27017
       ```
     - Example: If you see `0.0.0.0:27017`, MongoDB is accessible from any network interface.
   - **Docker Networks:**
     - Command:
       ```bash
       docker network ls
       docker network inspect <network>
       ```
     - Example: Inspect if all services are on the same network or if isolation is used.

3. **Check for Sensitive Data Exposure (with Examples)**
   - **Environment Variables:**
     - Command:
       ```bash
       docker inspect <container_id> | grep -i env
       ```
     - Example: Credentials or API keys visible in output.
   - **Mounted Volumes:**
     - Example: In `docker-compose.yaml`, you see `- ./data:/data/db`, which may expose host data to the container.
     - Command:
       ```bash
       docker inspect <container_id> | grep Mounts -A 10
       ```

4. **Document Threats and Mitigations (with Examples)**
   - Example Table:

| Threat Vector                | Example/Command                                      | Potential Impact         | Mitigation Strategy                |
|-----------------------------|-----------------------------------------------------|-------------------------|------------------------------------|
| Exposed MongoDB port        | `ports: - "27017:27017"`<br>`ss -tuln`              | Data theft, DoS         | Bind to localhost, use firewalls   |
| Weak credentials            | `MONGO_INITDB_ROOT_PASSWORD: example`                | Unauthorized access     | Use strong, unique passwords       |
| Untrusted images            | `mongo:4.2`<br>`trivy image mongo:4.2`               | Malware, vulnerabilities| Use official, scanned images       |
| Container runs as root      | No `user:` in YAML<br>`whoami` in container          | Privilege escalation    | Specify non-root user in Dockerfile|
| Sensitive data in env/vols  | `docker inspect <id> | grep -i env`/`Mounts`         | Data leakage            | Use secrets management, restrict volumes |

## Clean Up

After completing the lab, stop and remove the containers:

```bash
docker compose down
```

## Deliverable

Submit your completed threat model table and a brief summary of key risks and mitigations identified during the lab.
