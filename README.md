# Awesome Container Security [![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re)

List of awesome resources about container security, including books, blogs, videos, tools, and cases for Docker and Kubernetes.

## Table of Contents

- [🐳 Docker Security](#docker-security)
- [☸️ Kubernetes Security](#kubernetes-security)

## 🐳 Docker Security

### Books

- [Container Security by Liz Rice](https://learning.oreilly.com/library/view/container-security/9781492056690/)
- [Docker Security by Adrian Mouat](https://learning.oreilly.com/library/view/docker-security/9781492042297/)
- [Advanced Infrastructure Penetration Testing by Chiheb Chebbi](https://learning.oreilly.com/library/view/advanced-infrastructure-penetration/9781788624480/)

### Blogs

- [Docker Security](https://docs.docker.com/engine/security/)
- [OWASP Docker Security](https://github.com/OWASP/Docker-Security)
- [Introduction to Container Security Understanding the isolation properties of Docker](https://www.docker.com/sites/default/files/WP_IntrotoContainerSecurity_08.19.2016.pdf)
- [Anatomy of a hack: Docker Registry](https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/)
- [Hunting for Insecure Docker Registries](https://medium.com/@act1on3/hunting-for-insecure-docker-registries-d87d293e6779)
- [How Abusing Docker API Lead to Remote Code Execution](https://www.blackhat.com/docs/us-17/thursday/us-17-Cherny-Well-That-Escalated-Quickly-How-Abusing-The-Docker-API-Led-To-Remote-Code-Execution-Same-Origin-Bypass-And-Persistence_wp.pdf)
- [Using Docker-in-Docker for your CI or testing environment? Think twice](https://jpetazzo.github.io/2015/09/03/do-not-use-docker-in-docker-for-ci/)
- [Vulnerability Exploitation in Docker Container Environments](https://www.blackhat.com/docs/eu-15/materials/eu-15-Bettini-Vulnerability-Exploitation-In-Docker-Container-Environments-wp.pdf)
- [Mitigating High Severity RunC Vulnerability (CVE-2019-5736)](https://blog.aquasec.com/runc-vulnerability-cve-2019-5736)
- [Building Secure Docker Images - 101](https://medium.com/walmartlabs/building-secure-docker-images-101-3769b760ebfa)
- [Dockerfile Security Checks using OPA Rego Policies with Conftest](https://blog.madhuakula.com/dockerfile-security-checks-using-opa-rego-policies-with-conftest-32ab2316172f)
- [An Attacker Looks at Docker: Approaching Multi-Container Applications](https://i.blackhat.com/us-18/Thu-August-9/us-18-McGrew-An-Attacker-Looks-At-Docker-Approaching-Multi-Container-Applications-wp.pdf)
- [Lesson 4: Hacking Containers Like A Boss ](https://www.practical-devsecops.com/lesson-4-hacking-containers-like-a-boss/)
- [How To Secure Docker Images With Encryption Through Containerd](https://www.whitesourcesoftware.com/free-developer-tools/blog/secure-docker-with-containerd/)

### Videos

- [Best practices for building secure Docker images](https://www.youtube.com/watch?v=LmUw2H6JgJo)
- [OWASP Bay Area - Attacking & Auditing Docker Containers Using Open Source tools](https://www.youtube.com/watch?v=ru7GicI5iyI)
- [DockerCon 2018 - Docker Container Security](https://www.youtube.com/watch?v=E_0vxpL_lxM)
- [DockerCon 2019 - Container Security: Theory & Practice at Netflix](https://www.youtube.com/watch?v=bWXne3jRTf0)
- [DockerCon 2019 - Hardening Docker daemon with Rootless mode](https://www.youtube.com/watch?v=Qq78zfXUq18)
- [RSAConference 2019 - How I Learned Docker Security the Hard Way (So You Don’t Have To)](https://www.youtube.com/watch?v=C343TPOpTzU)
- [BSidesSF 2020 - Checking Your --privileged Container](https://www.youtube.com/watch?v=5VgSFRyI38w)
- [Live Container Hacking: Capture The Flag - Andrew Martin (Control Plane) vs Ben Hall (Katacoda)](https://www.youtube.com/watch?v=iWkiQk8Kdk8)

### Tools

#### Container Runtime

- [gVisor](https://github.com/google/gvisor) - An application kernel, written in Go, that implements a substantial portion of the Linux system surface.
- [Kata Containers](https://github.com/kata-containers/kata-containers) - An open-source project and community working to build a standard implementation of lightweight Virtual Machines (VMs) that feel and perform like containers but provide the workload isolation and security advantages of VMs.
- [sysbox](https://github.com/nestybox/sysbox) - An open-source container runtime that enables Docker containers to act as virtual servers capable of running software such as Systemd, Docker, and Kubernetes in them. Launch inner containers, knowing that the outer container is strongly isolated from the underlying host.
- [Firecracker](https://github.com/firecracker-microvm/firecracker-containerd) - An open-source virtualization technology that is purpose-built for creating and managing secure, multi-tenant container and function-based services.

#### Container Scanning

- [trivy](https://github.com/aquasecurity/trivy) - A simple and comprehensive Vulnerability Scanner for Containers, suitable for CI.
- [Clair](https://github.com/quay/clair) - Vulnerability Static Analysis to discovering Common Vulnerability Exposure (CVE) on containers and can integrate with CI like Gitlab CI which included on their [template](https://docs.gitlab.com/ee/user/application_security/container_scanning/).
- [Harbor](https://github.com/goharbor/harbor) - An open-source trusted cloud-native registry project that is equipped with several features such as RESTful API, Registry, Vulnerability Scanning, RBAC, and more.
- [Anchore Engine](https://anchore.com) - An open-source project that provides a centralized service for inspection, analysis, and certification of container images. Access the engine through a RESTful API and Anchore CLI, and integrate it into your CI/CD pipeline.
- [grype](https://github.com/anchore/grype) - An open-source project from Anchore to perform vulnerability scanning for container images and filesystems.
- [Dagda](https://github.com/eliasgranderubio/dagda/) - A tool to perform static analysis of known vulnerabilities, trojans, viruses, malware, and other malicious threats in Docker images/containers and to monitor the Docker daemon and running Docker containers for detecting anomalous activities.
- [Synk](https://snyk.io) - CLI and build-time tool to find and fix known vulnerabilities in open-source dependencies; supports container scanning and application security.

#### Compliance

- [Docker Bench for Security](https://github.com/docker/docker-bench-security) - A script that checks for dozens of common best practices around deploying Docker containers in production.
- [CIS Docker Benchmark - InSpec profile](https://github.com/dev-sec/cis-docker-benchmark) - Compliance profile implementing the CIS Docker 1.13.0 Benchmark in an automated way to provide security best-practice tests around Docker daemon and containers in a production environment.
- [lynis](https://github.com/CISOfy/Lynis) - Security auditing tool for Linux, macOS, and UNIX-based systems. Assists with compliance testing (HIPAA/ISO27001/PCI DSS) and system hardening. Agentless, and installation is optional.
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) - An open-source, general-purpose policy engine that enables unified, context-aware policy enforcement across the entire stack.
- [opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) - A policy-enabled authorization plugin for Docker.

### Pentesting

- [BOtB](https://github.com/brompwnie/botb) - Container analysis and exploitation tool designed to be used by pentesters and engineers while also being CI/CD friendly with common CI/CD technologies.
- [Gorsair](https://github.com/Ullaakut/Gorsair) - A penetration testing tool for discovering and remotely accessing Docker APIs from vulnerable Docker containers.
- [Cloud Container Attack Tool](https://github.com/RhinoSecurityLabs/ccat) - A tool for testing the security of container environments.
- [DEEPCE](https://github.com/stealthcopter/deepce) - A tool for Docker enumeration, escalation of privileges, and container escapes.

### Playground

- [Docker Security Playground (DSP)](https://github.com/giper45/DockerSecurityPlayground) - A Microservices-based framework for the study of network security and penetration test techniques.
- [Katacoda Courses: Docker Security](https://www.katacoda.com/courses/docker-security) - Learn Docker Security using Interactive Browser-Based Scenarios.
- [Docker Security by Control Plane](https://control-plane.io/training) - Learn Docker Security from Control Plane.
- [Play with Docker](https://labs.play-with-docker.com/) - A simple, interactive, fun playground to learn Docker, and it's **free**.
- [OWASP WrongSecrets](https://github.com/commjoen/wrongsecrets) - A vulnerable app covering bad practices in secrets management, including Docker.

### Monitoring

- [Falco](https://github.com/falcosecurity/falco) - Cloud Native Runtime Security.
- [Wazuh](https://wazuh.com) - Free, open-source, and enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response, and compliance.
- [Weave Scope](https://www.weave.works/oss/scope/) - Detects processes, containers, hosts. No kernel modules, no agents, no special libraries, no coding. Seamless integration with Docker, Kubernetes, DCOS, and AWS ECS.

### Others

- [dive](https://github.com/wagoodman/dive) - A tool for exploring each layer in a Docker image.
- [hadolint](https://github.com/hadolint/hadolint) - A smarter Dockerfile linter that helps you build best practice Docker images.
- [dockle](https://github.com/goodwithtech/dockle) - Container image linter that helps you build the best practices Docker image.
- [docker_auth](https://github.com/cesanta/docker_auth) - Authentication server for Docker Registry 2.
- [bane](https://github.com/genuinetools/bane) - Custom & better AppArmor profile generator for Docker containers.
- [secret-diver](https://github.com/cider-rnd/secret-diver) - Analyzes secrets in containers.
- [confine](https://github.com/shamedgh/confine) - Generate SECCOMP profiles for Docker images.
- [imgcrypt](https://github.com/containerd/imgcrypt) - OCI Image Encryption Package.
- [lazydocker](https://github.com/jesseduffield/lazydocker) - A tool to manage Docker images and containers easily.

## ☸️ Kubernetes Security

### Books

- [Kubernetes Security by Liz Rice](https://learning.oreilly.com/library/view/kubernetes-security/9781492039075/)
- [Kubernetes Best Practices by Brendan Burns](https://learning.oreilly.com/library/view/kubernetes-best-practices/9781492056478/)

### Blogs

- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/security-best-practices/)
- [Kubernetes Security and Observability Best Practices](https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-security-and-observability-best-practices)
- [Introduction to Kubernetes Security](https://www.cncf.io/blog/2019/08/29/introduction-to-kubernetes-security/)
- [The DevSecOps Guide to Kubernetes Security](https://www.stackrox.com/post/2021/03/the-devsecops-guide-to-kubernetes-security/)
- [Kubernetes Security Assessment](https://github.com/kubernetes/community/blob/master/WG-Security-Audit/Security-Assessment.md)

### Videos

- [Kubernetes Security Best Practices](https://www.youtube.com/watch?v=saCfLneaLJ0)
- [Kubernetes Security Fundamentals](https://www.youtube.com/watch?v=mCvx2jCHa80)
- [Securing Your Kubernetes Cluster - Kubernetes Security Best Practices](https://www.youtube.com/watch?v=_vHTaIJm9uY)
- [Secure your Kubernetes Cluster in Production - Kubernetes Security - Part 1](https://www.youtube.com/watch?v=8AMvP3gXdnk)
- [Secure your Kubernetes Cluster in Production - Kubernetes Security - Part 2](https://www.youtube.com/watch?v=8AVcVFsZ1XI)

### Tools

- [kube-bench](https://github.com/aquasecurity/kube-bench) - Checks whether Kubernetes is deployed securely by running the checks documented in the CIS Kubernetes Benchmark.
- [kube-hunter](https://github.com/aquasecurity/kube-hunter) - Hunts for security weaknesses in Kubernetes clusters, including attack scenarios, misconfigurations, and vulnerabilities.
- [kubeaudit](https://github.com/Shopify/kubeaudit) - A tool that audits Kubernetes clusters against common security controls.
- [kube-score](https://github.com/zegl/kube-score) - Kubernetes object scoring tool that checks against Kubernetes best practices.
- [Kubesec.io](https://kubesec.io/) - Kubernetes security risk assessment tool.
- [KubiScan](https://github.com/cyberark/KubiScan) - A tool that scans Kubernetes clusters for risky permissions and misconfigurations.
- [Kubei](https://github.com/Portshift/Kubei) - Kubernetes runtime images scanning and analysis tool.
- [kube-hunter-operator](https://github.com/deepfence/awesome-kubernetes-security/blob/master/kube-hunter-operator.md) - An operator to run kube-hunter as a pod in your Kubernetes cluster and get actionable findings as Kubernetes events.

### Blogs

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [Kubernetes Security Best Practices - by Aqua Security](https://www.aquasec.com/cloud-native-academy/kubernetes-security-best-practices/)
- [Kubernetes Security Best Practices - by Microsoft](https://azure.microsoft.com/en-us/resources/kubernetes-security-guide/)

### Videos

- [Kubernetes Security Best Practices](https://www.youtube.com/watch?v=qm0rLyvqf5c)
- [Kubernetes Security: Setting up Network Policies](https://www.youtube.com/watch?v=e4Gs1FBE2jo)
- [Kubernetes Security Best Practices - by Microsoft](https://www.youtube.com/watch?v=cqcILy5oSbI)
- [Kubernetes Security: The State of the Union](https://www.youtube.com/watch?v=2_dkkHFWcpo)

## Contributing

Your contributions are always welcome!
