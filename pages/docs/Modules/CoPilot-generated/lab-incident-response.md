# Lab: Container Incident Response (Ubuntu 24.04 Guide)

## Objective
Detect and respond to a simulated security incident in a Docker environment on Ubuntu 24.04.

## Prerequisites
- Ubuntu 24.04 system (VM or bare metal)
- Docker Engine installed (`sudo apt update && sudo apt install docker.io -y`)
- (Optional) Falco installed for runtime threat detection (`sudo apt install falco -y`)

## Lab Steps

1. **Simulate a Suspicious Container**
   - Start a container that runs a simple web server:
     ```bash
     docker run -d --name webdemo -p 8080:80 nginx:alpine
     ```
   - Simulate suspicious activity (e.g., create a reverse shell or run an unexpected process):
     ```bash
     docker exec -it webdemo sh
     # Inside the container, run:
     nc -l -p 4444 &
     ```

2. **Review Container Logs and Monitoring Data**
   - Check container logs:
     ```bash
     docker logs webdemo
     ```
   - List running processes in the container:
     ```bash
     docker exec webdemo ps aux
     ```
   - (Optional) Use Falco to detect suspicious activity:
     ```bash
     sudo falco
     ```

3. **Identify Indicators of Compromise**
   - Look for unexpected processes (e.g., `nc`), open ports, or suspicious log entries.
   - Check for unusual network connections:
     ```bash
     docker exec webdemo netstat -tulnp
     ```

4. **Contain the Affected Container and Collect Evidence**
   - Pause or stop the container to prevent further damage:
     ```bash
     docker pause webdemo
     # or
     docker stop webdemo
     ```
   - Export the container filesystem for forensic analysis:
     ```bash
     docker export webdemo > webdemo.tar
     ```
   - Save logs and process lists for your report.

5. **Document Your Response and Recommend Improvements**
   - Write a summary of the incident, steps taken, and recommendations (e.g., enable runtime monitoring, restrict container capabilities, use non-root users).

## Deliverable
Submit your incident report, evidence collected (logs, exported container), and recommendations for improving container security and response.
