\# Wazuh SIEM \& Sysmon Home Lab



A hands-on threat detection, monitoring, and Security Operations Center (SOC) home lab environment built using \*\*VMware Workstation Pro\*\*, \*\*Wazuh SIEM\*\*, \*\*Sysmon\*\*, and \*\*Kali Purple\*\* for adversarial simulation.



\---



\## 🛠️ Project Architecture \& Asset Inventory



| Hostname | Role / OS | IP Address / Network | Telemetry / Agent |

| :--- | :--- | :--- | :--- |

| \*\*Wazuh-Server\*\* | SIEM / Ubuntu Server | Static (Internal Network) | Wazuh Manager \& Dashboard |

| \*\*Win10-Endpoint\*\* | Target / Windows 10 Pro | DHCP (Internal Network) | Wazuh Agent + Sysmon |

| \*\*Ubuntu-Endpoint\*\* | Target / Ubuntu Server | DHCP (Internal Network) | Wazuh Agent + Sysmon for Linux |

| \*\*Kali-Purple\*\* | Attacker / Kali Purple | DHCP (Internal Network) | None (Offensive Node) |



\### Core Data Flow

1\. \*\*Endpoint Telemetry:\*\* Microsoft System Monitor (\*\*Sysmon\*\*) captures low-level kernel and system events locally on the target endpoints.

2\. \*\*Secure Ingestion:\*\* The local \*\*Wazuh Agent\*\* reads and streams these telemetry logs securely to the \*\*Wazuh Server Manager\*\*.

3\. \*\*Correlation \& Indexing:\*\* The Manager processes and correlates incoming logs against detection rules before sending them to the Wazuh Indexer.

4\. \*\*Visualization:\*\* Analysts view and investigate alerts in real-time via the \*\*Wazuh Dashboard\*\*.



\---



\## ⚙️ Deployment \& Configuration Highlights



\- \*\*Wazuh Server:\*\* Deployed on Ubuntu Server using the official automated installation script; accessed via HTTPS (Port 443).

\- \*\*Windows Sysmon:\*\* Configured using a hardened baseline configuration file (`sysmonconfig.xml`) via PowerShell:

&#x20; ```powershell

&#x20; .\\Sysmon64.exe -accepteula -i sysmonconfig.xml

