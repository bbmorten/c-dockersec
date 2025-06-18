# Answers: Monitoring & Incident Response Quiz

1. **What are two key sources of logs in a Docker environment?**
   - Container stdout/stderr logs and Docker daemon logs.
2. **How can you detect suspicious activity in running containers?**
   - By monitoring logs, using runtime security tools (e.g., Falco), and checking for unusual processes or network connections.
3. **True or False: Stopping a compromised container is always the best first response.**
   - False. Sometimes it's better to isolate and investigate before stopping to preserve evidence.
4. **What is the purpose of container runtime monitoring tools?**
   - To detect, alert, and respond to suspicious or malicious activity in real time.
5. **Name one best practice for incident response in containerized environments.**
   - Automate detection and response, maintain audit logs, and have a documented incident response plan.
