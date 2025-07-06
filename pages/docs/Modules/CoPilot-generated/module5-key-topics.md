# Module 5 Key Topics: Monitoring, Logging, and Incident Response

## Logging Best Practices
- Use stdout/stderr for container logs.
- Configure log drivers and centralize logs for analysis.

**Diagram: Centralized Logging**

```
[Container]--(stdout)-->[Docker Daemon]--(log driver)-->[Central Log Server]
```

**References:**
- [Docker Docs: Configure logging drivers](https://docs.docker.com/config/containers/logging/configure/)
- [ELK Stack for Docker Logging](https://www.elastic.co/guide/en/ecs-logging/overview.html)

## Intrusion Detection and Runtime Monitoring
- Deploy Falco, auditd, or similar tools for real-time monitoring.
- Set up alerts for suspicious activity.

**Diagram: Intrusion Detection**

```
[Container] --> [Falco/auditd] --> [Alert/Event]
```

**References:**
- [Falco Project](https://falco.org/)
- [Auditd Documentation](https://linux.die.net/man/8/auditd)

## Incident Response Workflows
- Develop playbooks for common container incidents.
- Practice evidence collection and forensic analysis.

**Diagram: Incident Response Flow**

```
[Detection] -> [Analysis] -> [Containment] -> [Eradication] -> [Recovery]
```

**References:**
- [NIST: Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
- [Docker Docs: Security best practices](https://docs.docker.com/engine/security/security/)

## Log and Event Analysis
- Analyze logs for signs of compromise or misconfiguration.
- Use tools like ELK stack or Grafana Loki for visualization.

**References:**
- [Grafana Loki](https://grafana.com/oss/loki/)
- [ELK Stack](https://www.elastic.co/what-is/elk-stack)

## Automating Alerts and Responses
- Integrate monitoring tools with alerting systems (e.g., Slack, email).
- Automate containment or remediation steps where possible.

**References:**
- [Prometheus Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/)
- [PagerDuty](https://www.pagerduty.com/)
