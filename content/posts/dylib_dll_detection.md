---
draft: false
title: 'Looking through the windows: A pragmatic approach for dylib hijacking detection'
date: 2025-10-20
description: 
---

Inspired by Patrick Wardle's talk at [OBTSv8](https://objectivebythesea.org/v8/) (Dylib Hijacking on macOS: Dead or Alive?) I wanted to ask the question “What can we learn from DLL hijacking on Windows to improve dylib hijacking detection on macOS?”
<!--more-->

## DLL Hijacking

DLL Hijacking is a technique that takes advantage of a system’s search order to get a legitimate and trusted application to load an arbitrary (ideally malicious) DLL. 

### Why Hijack?

* Execution: run malicious code through a trusted executable.
* Persistence: the target application might be part of the OS or an innocuously persistent application.
* Privilege escalation: the injected library is executed with the same privileges as the application. If the application has elevated permissions, these permissions will be inherited by the malicious library.

DLL hijacking is further divided into sub techniques, depending on how the application is configured to load DLLs. Attackers may replace a legitimate DLL, hijacking the search order or drop an malicious DLL in place of a missing (phantom) DLL that the application tries to load (and more). Whilst these all exploit the same principle to load a malicious DLL into legitimate processes, they provide subtly different opportunities for detection.

Check out the following resources for a more detailed overview of the technique on [Windows](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows) and [macOS](https://www.virusbulletin.com/uploads/pdf/magazine/2015/vb201503-dylib-hijacking.pdf).
 
## What can we learn from DLL hijacking on Windows for macOS detection?

### Classifying hijacking sub-techniques provides detection value
Each type of DLL hijacking has varying degrees of stealthiness and unique indicators for detection. In the case of DLL replacement, the attacker will have to delete the native DLL. In the case of search order hijacking, two identically named DLLs may be present on the system.

### Stealthyness and assumed priviledge levels
The more stealthy implementations of DLL hijacking on Windows require a user that already has privileges to write locations higher in the search order, which are usually the protected locations like system32. 

To avoid this problem, in most cases attackers are dropping an executable on the system with the malicious library in the same directory. This is because the directory in which the application is installed is higher in the search order and user writable. DLLs loaded outside of protected locations should always arouse more suspicion, because they don’t require these privileges to be placed there.

The same principles translate to macOS, with attackers in the wild seen bringing their own repackaged versions of legitimate applications with the malicious dylibs, rather than exploiting applications already installed on disk. Apps executed from unexpected or unprivileged locations (such as outside of the applications directory on macOS) are more suspicious.

### When to detect? file creation vs load time
There are two clear opportunities to detect DLL hijacking. When the malicious DLL is dropped to disk, and when it is loaded by an application. These events might happen in short succession, but it is conceivable that they are not. For example, the application is added to a persistence location so runs on the next trigger (such as startup). 

### Signature information is a must for low hanging fruit
Security tooling must be able to evaluate signature information of the libraries loaded by applications at runtime. This opens behaviour-based detections such as unsigned apps that load unsigned dylibs, or apps loading libraries with a different signature. For example, a neat DLL hijacking implementation using custom KQL on Defender takes this further using the [FileProfile()](https://medium.com/@kozielpawe/detecting-dll-hijacking-made-simple-with-hijacklibs-and-kql-1ddec9b7fe1b) function to enrich DLLs loaded at runtime with file information such as the publisher, digital signature information, size, prevalence, hash values etc.

However signature information is not a catch all. There are many instances dylib hijacking where both the application and dependency have been signed by the developer or even notorised, such as the [3CX](https://objective-see.org/blog/blog_0x73.html) supply chain attack.

### Don’t let fear of missing the unknown stop you from detecting the known
Threat actors are lazy. In the Windows domain, threat actors can be seen abusing the same binaries, and looking for these known cases is better than looking for nothing at all. For example, abuse of [goopdate.dll ](https://www.ncsc.gov.uk/static-assets/documents/malware-analysis-reports/goofy-guineapig/NCSC-MAR-Goofy-Guineapig.pdf). There will always be vulnerable applications that attackers re-use, and talented reverse engineers who to provide high fidelity indicators.

### Not every theoretical hijack is actually one
As a detection engineer, DLL hijacking is one of those techniques that feels overwhelming. With every system application being a potential target, and endless third-party applications that will be vulnerable, it feels impossible to have anything resembling coverage.

The silver lining is that not every application that could be targeted would be targeted. Given the attacker intends to gain persistence or privileges or code execution under the guise of a trusted process, attackers should target privileged, common or noisy applications.

### Real environments are noisy
It is not enough in an enterprise security context to detect hijacking based on the applications that are theoretically hijackable. There are some excellent tools on Windows and macOS that do this, such as [Dylib Hijack Scanner](https://objective-see.org/products/dhs.html) or the Windows project [Hijacklibs]( https://hijacklibs.net/). 

But as a scalable hijacking detection strategy, this approach will drown a SOC. In my experience, real environments do not conform to theoretical operating systems, and are full of third-party software that will run out of unexpected locations and load all sorts of stuff for 'legitimate' reasons.

### Relegate from real time detection
Much like real-time detection for persistence mechanisms, there is a sense in which it is insurmountable to design a complete real time detection system for DLL/dylib hijacking. Less stealthy implementations might be possible to flag in real time, but we should admit that some techniques are simply better suited to a hunting-based approach.

### AI solve everything
Whilst I am generally skeptical of mysterious 'AI' powered detection, this feels like a good use case where machine learning can help. Not so much for finding the bad, but for filtering out the known good. 

Consider an EDR with environment wide visibility recording all DLL/dylib loads made by all processes/applications. EDR could then make decisions about whether a library loaded into a specific process should be considered rare across an environment. This primitive is even stronger with visibility of multiple tenants, something analogous to file prevalence, but for DLL loads.

### The human factor
Yes DLL/dylib hijacking is a sophisticated technique which presents challenges for detection, particularly around blending in with legitimate noise. But how are users going to be tricked into running these applications in the first place? In the mac ecosystem, these are delivered by installers, again intriducing its own opportunity for detection.

### Context
Dylib hijacking does not need to be detected in a vacuum. Primarily the technique in the wild on macOS is being used as a dropper. The application will go on to download and execute follow-on payloads. These might make suspicious network connections, spawn child processes, write files. The application will likely be added to a persistence location, which when paired with the fact it is theoretically hijackable, or any other detection primitive, may present a more realistic detection criteria.

### Time for temporal logic
One of the limiting factors in commercial detection tooling is not more telemetry, but a more mature detection language. The ability to define real-time detection logic based on a sequence of events in time that are not connected by parent > child relationships. 

With a detection logic that could specify that events occur within a time period on the same endpoint, then this could reach the threshold of malicious activity to generate high fidelity, real-time detections for dylib hijacking. 

Consider:

| Action      | Is it normal? | Threshold for suspicious    |
| :---        |    :----:   |          ---: |
| dmg for signed and notarized binary is executed      | User download software all the time      | :red_circle:  |
| An application theoretically vulnerable to dylib hijacking is installed   | Users can install whatever software they like        | :red_circle:     |
| A signed application launches an unsigned dylib | Commonly observed for third-party tools | :red_circle: |
| An application is added to a persistence location | Legitimate software is commonly addeed to persistence locations | :red_circle: |
| All of the above| :triangular_flag_on_post: | :green_circle: 

Whilst this sounds completely intuitive, I have not personally encountered an implementation of temporal logic in a commercial EDR tool. The main implementations for this instead occur in upstream layers like the SIEM, or tools which try and group clusters of indepedent alerts on a host into incidents. In my experience, this leads to single anomalous alerts being grouped with alerts that probably should have already been suppressed, into ambigious incidents.

## TLDR

* DLL hijacking can be broken into sub-techniques, of varying stealthiness with their own opportunities for detection.
* In a lot of cases, attackers will drop the legitimate application with the malicious library, rather than exploit applications that are already installed, a technique also seen on macOS.
* Signing information is important for detection but not a catch all, with many examples of malicious hijacked applications and their dylibs being signed and notorised.
* Combining a suspicious DLL/dylib with additional context such as any persistence mechanisms, enriched file information and process behaviours is essential to creating a scaleable and high-fidelity detection approach.