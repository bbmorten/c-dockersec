# Online Course Creation Prompt Template

## Parameters

- **TOPIC**: Docker Security
- **DIFFICULTY_LEVEL**: Advanced
- **TARGET_AUDIENCE**: IT professionals, software developers, system administrators and network administrators
- **COURSE_DURATION**: 5 days (24 hours total)
- **LEARNING_OBJECTIVES**:
  - Assess and mitigate container security risks by identifying common vulnerabilities in Docker images, containers, and orchestration platforms, and implementing appropriate security controls
  - Design and implement secure Docker environments using security best practices including image scanning, runtime protection, network segmentation, and access controls
  - Configure Docker security features such as user namespaces, seccomp profiles, AppArmor/SELinux policies, and resource limitations to create hardened container environments
  - Analyze and respond to container security incidents by monitoring container behavior, detecting anomalies, and implementing incident response procedures specific to containerized environments
  - Establish secure CI/CD pipelines that integrate security scanning, vulnerability management, and compliance checks throughout the container development lifecycle
  - Implement enterprise-grade container security strategies including secrets management, image registry security, multi-tenancy considerations, and compliance with industry standards (CIS, NIST, etc.)
- **SPECIAL_REQUIREMENTS**:
  - **Prerequisites**: Basic Docker experience (container creation, running containers, dockerfile writing), fundamental Linux command line knowledge, basic understanding of networking concepts
  - **Technical Requirements**: Docker Desktop or Docker Engine installed, access to a Linux environment (VM or WSL2), Git version control system, code editor (VS Code recommended with Docker extension)
  - **Linux Knowledge Requirements**: 
    - File system navigation and permissions (ls, cd, chmod, chown)
    - Process management and monitoring (ps, top, kill, systemctl)
    - Network troubleshooting commands (netstat, ss, iptables basics)
    - Log file analysis and system monitoring (tail, grep, journalctl)
    - Package management for security updates (apt)
    - User and group management for container security contexts
  - **Cloud Access**: Access to at least one cloud provider (AWS, Azure, or GCP) for container registry and orchestration examples
  - **Hardware**: Minimum 8GB RAM, 20GB available disk space for container images and tools
  - **Security Tools**: Familiarity with security concepts, access to security scanning tools, basic understanding of authentication and authorization principles
- **DELIVERY_FORMAT**: Online self-paced course with video lectures, hands-on labs, quizzes, and a final project
- **ASSESSMENT_TYPE**: Projects, quizzes

## The Prompt

Please create a comprehensive online course on **[TOPIC]** designed for a **[DIFFICULTY_LEVEL]** level **[TARGET_AUDIENCE]**. The course should be structured to be completed in **[COURSE_DURATION]**.

By the end of this course, students should be able to:
**[LEARNING_OBJECTIVES]**

The course will be delivered in a **[DELIVERY_FORMAT]** format and will include **[ASSESSMENT_TYPE]** for student evaluation.

Please develop the following elements for this course:

1. A compelling course title and brief marketing description (2-3 sentences)
2. A comprehensive course overview explaining the value and relevance of this topic
3. A detailed syllabus with:
   - 4-10 main modules/units
   - Learning objectives for each module
   - Key topics covered in each module
   - Estimated time commitment for each module
   - Suggested learning activities and resources
4. Assessment strategy including:
   - Formative assessments throughout the course
   - Summative assessment(s) to evaluate overall learning
   - Grading criteria if applicable
5. A list of required and recommended materials/resources
6. Prerequisites or technical requirements (**[SPECIAL_REQUIREMENTS]**)
7. Suggestions for making the course engaging and interactive
8. Ideas for potential course extensions or advanced follow-up topics

Please ensure the course structure follows educational best practices, incorporates varied learning activities, and addresses different learning styles.
