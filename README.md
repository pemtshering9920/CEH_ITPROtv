# CEH_ITPROtv

[x] Threat Hunting: Key Concepts and Details
Objective of Threat Hunting:

Discover data breaches by thoroughly examining systems for any signs of compromise.
Identify and categorize Indicators of Compromise (IoCs), which help in detecting security incidents.
List common IoCs to recognize possible attack patterns.
What is Threat Hunting?
Threat hunting is a proactive security practice where security teams actively search for threats or breaches in the system.
Unlike traditional security tools that wait for alerts, threat hunters assume a breach has already occurred and search for signs of it.
According to research, it takes an average of 212 days to discover a breach and an additional 75 days to contain it. This highlights the importance of threat hunting to reduce this time frame.
Source: VentureBeat Article on Breach Detection.
Steps in Performing Threat Hunting:
Hypothesize the Most Likely Attack:

Threat hunters start by making an educated guess about which type of attack could be targeting the system, based on the organization's profile and recent cyber threats.
Look for Suspicious, Malicious, or Risky Activity:

Once a hypothesis is in place, hunters search for any unusual activity in the system that might support or disprove their hypothesis.
Generate Indicators of Compromise (IoCs) and Alerts:

During the search, threat hunters may come across IoCs that serve as evidence of a breach, which can then trigger alerts for further investigation.
What is an Indicator of Compromise (IoC)?
An IoC is a piece of evidence that points to a security breach. It's like a digital footprint left behind by attackers.
IoCs are usually collected after a suspicious incident or security event has been identified.
Types of IoCs:
Atomic: Self-contained data points like IP addresses or email addresses.
Computed: Data derived from system analysis, such as hash values or regular expressions (RegEx).
Behavioral: A combination of atomic and computed data that points to a suspicious pattern of activity.
IoC Categories:
IoCs can be classified into the following categories:

Email Artifacts:

Sender's email address: Could be spoofed or compromised.
Subject line: Suspicious or misleading.
Attachments: Could contain malware.
Links: May lead to malicious websites.
Network Artifacts:

Domain info: Malicious or unknown domains involved in the attack.
IP addresses: Suspicious IPs that interact with the network.
Host-Based Artifacts:

File names: Suspicious or newly introduced files.
Hash values: Identifiers for files, especially malware.
Registry entries: Abnormal or new entries in system registries.
Drivers: Malicious or unauthorized drivers installed.
Behavioral Artifacts:

Macros running PowerShell: Attackers can use macros to execute malicious scripts.
Service accounts running commands like a user: Unusual activities performed by service accounts, which typically shouldn't perform manual commands.
Examples of IoCs:
Here are some practical examples of what might be flagged as an IoC during threat hunting:

Privileged User Activity anomalies: Unusual access patterns by high-privilege users.
Red flags in login activity: Repeated failed login attempts or logins at strange times.
Deviant DNS requests: Requests to domains that the system doesn’t usually interact with.
Web traffic exhibiting inhuman behavior: Unusually fast or repetitive behavior indicating bot activity.
Unusual outbound network traffic: Large amounts of data being sent outside the network.
Geographical abnormalities: Logins from multiple locations in a short period.
Increased database read volume: Large-scale access to sensitive data.
Unusual HTML response sizes: Suspiciously large or small web response data.
Changes in mobile device profiles: Unusual changes to device settings or profiles.
Signs of DDoS activity: Large amounts of network traffic aimed at overwhelming a server.
Misplaced data bundles: Sensitive data stored in incorrect or unauthorized places.
Conflicting port-application traffic: Unexpected use of ports by applications.
More requests than usual for the same file: Repeated access to a particular file.
Unusual changes in registry/system files: Sudden modifications to important system files.
Abrupt system patching: Sudden updates or patches applied without explanation, which could cover up malicious activity.
Conclusion:
Threat hunting is an essential cybersecurity practice that involves actively looking for threats within a system. It aims to identify Indicators of Compromise (IoCs), which provide evidence of security breaches. Understanding the categories and examples of IoCs allows security teams to detect and respond to potential threats more effectively, minimizing the damage caused by cyberattacks​
