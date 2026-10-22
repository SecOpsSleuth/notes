+++
title = 'Tools'
description = 'Cloud incident response tools'
toc = false
+++

Cloud incident response tools.

## Tools overview

| Tool | Purpose | Link |
|--------|----------|---------|
| [OneClickEvict](#oneclickevict) | Contain, remediate, and restore compromised Microsoft Entra ID accounts | *Private* |
| [PyHuntKQL](#pyhuntkql) | Python-powered threat hunting with KQL superpowers | *Private* |

## OneClickEvict

Contain, remediate, and restore compromised Microsoft Entra ID accounts.

Uses Microsoft Graph to automate the response actions for a compromised Entra ID identity. It disables accounts and revokes tokens at scale, uses Conditional Access policies to cover hybrid environments, and tracks remediation through security groups. It also removes malicious inbox rules, registered applications and app consents, and securely resets passwords in bulk.

![OneClickEvict home page](oneclickevict/1-home.png)
*Home page*

![Loading users into OneClickEvict](oneclickevict/2-load-users.png)
*Load users*

![Configuring and running Contain](oneclickevict/3-contain.png)
*Configure and run Contain*

![Configuring and running Remediate](oneclickevict/4-remediate.png)
*Configure and run Remediate*

![Configuring and running Restore](oneclickevict/5-restore.png)
*Configure and run Restore*

**Link:** *Private*

## PyHuntKQL

Python-powered threat hunting with KQL superpowers.

A validated repository of high-quality KQL hunts, including quick-to-deploy packs for incident response. No SIEM is required: it queries Defender tables directly through the Advanced Hunting API and returns only the hunts with matches. Built-in KQL validation and schema checks mean it only issues hunts that can return results, reducing false negatives. Repeatable hunting as code, with no manual hunting time.

![PyHuntKQL home page](pyhuntkql/1-home.png)
*Homepage*

![PyHuntKQL Query Viewer](pyhuntkql/2-query-viewer.png)
*Query Viewer - KQL detection-as-code threat hunting repository*

![Go Hunting: OAuth application and query schema](pyhuntkql/3-go-hunting-setup.png)
![Go Hunting: configure hunt](pyhuntkql/4-go-hunting-configure.png)
*Go Hunting - register OAuth application, apply KQL schema, configure the queries and hunt*

![PyHuntKQL Analyse Results](pyhuntkql/5-analyse-results.png)
*Analyse Results - see only the matches*

**Link:** *Private*
