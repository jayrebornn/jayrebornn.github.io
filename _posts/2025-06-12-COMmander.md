---
layout: post
title: COMmanding COM Telemetry  - A look into RPC calls
thumbnail-img: /assets/img/commander/COMmander.png
share-img: /assets/img/commander/COMmander.png
tags: [COM, DCOM, RPC, Windows Internals, Detections]
---



# Introduction 

This is some research into RPC and detecting COM and DCOM attacks that @hullabrian and I worked on during our free time. This is something that can hopefully make detection
on advanced attacks more easily. 

The GitHub can be found on https://github.com/HullaBrian/COMmander

Over the past year, we have seen an increase in Component Object Model (COM) and Distributed Component Object Model (DCOM) attacks. 
These protocols use Remote Procedure Calls (RPC), which allow communication between two distributed component objects. Within these RPC calls, there are RPC interfaces; these are
the methods within the object that define the capabilities of the COM object and allow us to get an idea of the actions being performed. Following these interfaces 
allows us to track any malicious behavior and create detections based on the activity. 

There are not many ways to follow COM and DCOM-based attacks, as no tools really track RPC activity. So we wanted to find a new way to detect these attacks as a way to continue to monitor communication between 
systems, and learn a little more about Windows internals. We won't go too much into the actual attacks and how they work, just the process of building the detections for our tool and potential IoCs within the RPC communication.
This is where our tool COMmander comes into play, it is based on C# and when run will start a Windows RPC ETW session and continue to monitor the traffic looking for specific rules and create alerts when traffic is met. 
There are two ways of using COMmander, either as a service that creates Windows Event Logs or as a command-line tool that alerts in the terminal.




- [Introduction](#introduction)
- [Installing COMmander](#COMmander)
- [Attacks](#attacks)
  - [DefendNot](#defendnot)
  - [ForsHops](#forshops)
  - [RemoteRegistry](#remoteregistry)
  - [PetitPotam](#petitpotam)
  - [DCSync](#dcsync)
- [Conclusion](#conclusion)
- [References](#references)




# Installing COMmander

To start using COMmander Service, get the binary from the releases tab on GitHub. Within the release, there will be a setup binary that you can run that will add the binary to services and enable auto-start. After running in a privileged PowerShell environment, you can see that the service is running and enabled on startup.
There is also a script that will stop the COMmander binary and remove it from your system. 

![image](/assets/img/commander/commander-service.png)

We can also check the resource utilization of COMmander in Task Manager, and see that it is not a resource-intensive process.

![image](/assets/img/commander/commander-task-manager.png)

Now with the service running in the background, anytime an alert is detected, we will get a Windows Event Log and be able to investigate the alert further. To view these alerts, we can go to the Application and Services events in Event Viewer, and COMmander will be in the drop-down. 

![image](/assets/img/commander/commander-ev.png)

Now, when an alert is triggered, we will get information on the components that can be used to investigate the alert. 

![image](/assets/img/commander/commander-event.png)

# DefendNot

The first detection we made and what inspired this project was an attack called `DefendNot` created by `es3n1n`. This was a unique attack where you can manipulate the Windows Security Service (WSC) to register your anti-virus, which in turn disables Microsoft Defender. 
We can download the file using the GitHub repo for the tool. Once we have it on our machine, it is as easy as running the `defendnot-loader.exe`  and passing any parameters we like.

![image](/assets/img/commander/commander-defendnot.png)

Then we can go to the Windows Security Center and see that the registered antivirus is the name that we passed, and MDE has been disabled. 

![image](/assets/img/commander/commander-MDE.png)

Now that we see that it is possible, we want to build a detection for the attack using COMmander. So we can use a tool like RPCMon, which allows us to see the RPC communication. We should also use System Informer to see the running processes and get the PID related to WSC. 
After starting the attack and using System Informer, we see the different PIDs related to defendnot, and we can use them to search for our Interface UUIDs in RPCMon. 

![image](/assets/img/commander/commander-sysinformer.png)

Reading the blog post, we know that Taskmgr.exe (or the injected process) will be the one to send commands, so we will look for PID 7212. We only need to understand the functions being called and the Interface UUID being used, after that it doesn't matter if the injected process changes. 

![image](/assets/img/commander/commander-rpcmon.png)

After finding our PID, we see some important information that we can base our detections on. Interface UUID - `06bba54a-be05-49f9-b0a0-30f790261023` 

Module - `wscsvc.dll`

Function - `s_wscRegisterSecurityProduct` 

There are a couple of GitHub pages that have a dump of RPC functions. In this case, we will use the one by `enigma0x3`; all we need to do is search for our interface by either the name or UUID.

![image](/assets/img/commander/commander-dump.png)

We can then see that the function that was called in RPCMon `s_wscRegisterSecurityProduct` is assigned Opnum 13. An Opnum is essentially the interface function that the client is calling. 
Using these IoCs, we can now build our detection for COMmander. 

The format for the detections in COMmander is XML, so our custom detection for DefendNot will look like.

```
<Rule name="defendnot">
	<InterfaceUUID>06bba54a-be05-49f9-b0a0-30f790261023</InterfaceUUID>
	<OpNum>13</OpNum>
	<Endpoint></Endpoint>
 </Rule>
```

To test our detection, we want to make sure that the COMmander service is running. We can do this in the service application. 

Now we can execute the defendnot attack, and then check our Event Logs to see if an alert is generated.

![image](/assets/img/commander/commander-attack.png)

Now, checking our Event Logs, we see that the attack was detected. 

![image](/assets/img/commander/commander-ev1.png)

If we expand the alert, we will get additional information about the alert that can aid us in the investigation. 

![image](/assets/img/commander/commander-enrich.png)




# ForsHops

The next attack we will talk about is `ForsHops`  by `Dylan Tran` and `Jimmy Bayne`. This attack is noted as a way to use DCOM for fileless lateral movement. 

For this attack to work, we need to pass a file and an IP address. For testing purposes, we will use localhost and Cable.exe, a tool created by `@logan-goins`

![image](/assets/img/commander/forshops.png)

This is our command line argument, however, before we execute, we will want to ensure that RPCMon is running to view the connections.

After we run we need to stop RPCMon and search for the process name `ForsHops` from here we will see all activity related to the attack.

![image](/assets/img/commander/forshops-rpc.png)

We see the interface that is being used is `338CD001-2244-31F1-AAAA-900038001003`

This interface is used for Remote Registry services and is uncommon to see in day-to-day operations. So any activity should be alerted to, which allows analysts to further triage the events. 

The ruleset for this detection will look like this.

```
\<Rule name="Remote Registry Connection">
	\<InterfaceUUID>338cd001-2244-31f1-aaaa-900038001003</InterfaceUUID>
	\<Endpoint>\PIPE\winreg</Endpoint>
\</Rule>
```

We can run ForsHops with the following parameters. 

![image](/assets/img/commander/forshops-execute.png)

After seeing that the attack was successful, we can see that the RemoteRegistry alert was detected. 

![image](/assets/img/commander/forshops-detection.png)

We can also see that we are given information that can provide additional information on the alert and can help our investigation. 

![image](/assets/img/commander/forshops-enrich.png)




# RemoteRegistry

After making the `ForsHops`  detection we continued testing and found that the interface winreg.dll had a specific function that was seen in multiple attacks. This function was the `BaseRegSaveKey` function and is assigned `OpNum 20` . This function is used by attackers as it makes the enumeration of entire registry hives easy. Making this into a detection allows us to alert on any attack looking to dump credentials. 

Some of the attacks we saw that were alerted on are: 

`netexec` 

`Impacket Tools` like `secretsdump.py` 

`dploot`  (except the triage parameter)

To create a detection, we can use a rule like: 

```
<Rule name="Remote Registry BaseRegSaveKey">
	<InterfaceUUID>338cd001-2244-31f1-aaaa-900038001003</InterfaceUUID>
	<Endpoint>\PIPE\winreg</Endpoint>
	<OpNum>20</OpNum>
</Rule>
```

In this example, we will show NetExec being detected. For this to work, we will need to set up a Kali machine (attacker) and make sure that it can reach our victim computer with COMmander running. 

![image](/assets/img/commander/reg-nxc.png)

After running the attack, we see that COMmander detects the attack based on the BaseRegSaveKey being called. 

![image](/assets/img/commander/reg-nxc-event.png)




# PetitPotam

This attack is known as an NTLM Relay attack and can be used to coerce a host to authenticate to another machine, allowing privilege escalation. The GitHub that describes the attack gives us two Interfaces that we can build our detection on. The first is `c681d488-d850-11d0-8c52-00c04fd90f7e`, and the second is `df1941c5-fe89-4e79-bf10-463657acf44d` 

![image](/assets/img/commander/petitpotam.png)

We can also look at the Microsoft documentation and find the OpNums 

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/403c7ae0-1a3a-4e96-8efc-54e79a2cc451

With the interfaces and OpNums in the documentation, we can base our detection on these rules.

```
<Rule name="Authentication Coercion using PetitPotam EfsRpcOpenFileRaw">
		<InterfaceUUID>c681d488-d850-11d0-8c52-00c04fd90f7e</InterfaceUUID>
		<OpNum>0</OpNum>
		<ProcessName>lsass</ProcessName>
	</Rule>
	<Rule name="Authentication Coercion using PetitPotam EfsRpcEncryptFileSrv">
		<InterfaceUUID>c681d488-d850-11d0-8c52-00c04fd90f7e</InterfaceUUID>
		<OpNum>4</OpNum>
	</Rule>
	<Rule name="Authentication Coercion using PetitPotam EfsRpcDecryptFileSrv">
		<InterfaceUUID>c681d488-d850-11d0-8c52-00c04fd90f7e</InterfaceUUID>
		<OpNum>5</OpNum>
	</Rule>
	<Rule name="Authentication Coercion using PetitPotam EfsRpcQueryUsersOnFile">
		<InterfaceUUID>c681d488-d850-11d0-8c52-00c04fd90f7e</InterfaceUUID>
		<OpNum>6</OpNum>
	</Rule>
	<Rule name="Authentication Coercion using PetitPotam EfsRpcQueryRecoveryAgents">
		<InterfaceUUID>c681d488-d850-11d0-8c52-00c04fd90f7e</InterfaceUUID>
		<OpNum>7</OpNum>
	</Rule>
	<Rule name="Authentication Coercion using PetitPotam EfsRpcAddUsersToFile">
		<InterfaceUUID>c681d488-d850-11d0-8c52-00c04fd90f7e</InterfaceUUID>
		<OpNum>9</OpNum>
	</Rule>
```
We will need to have a Kali machine that can reach our Windows machine running COMmander. Then we can start the attack and see if an alert is detected. We can use the following command to start the attack.  

![image](/assets/img/commander/petitpotam-cli.png)

After seeing that the attack was successful, we can look at Event Viewer and see that an alert was generated. 

![image](/assets/img/commander/petitpotam-ev.png)




# DCSync

Our next detection is to detect DCSync attacks. This attack allows the attacker to impersonate the Domain Controller (DC), which allows them to create a replica of the data stored on the DC. 

For this attack, we can use secretsdump.py 

![image](/assets/img/commander/secretsdump.png)

Now we can go to Event Viewer and see that an alert has been generated. 

![image](/assets/img/commander/secretsdump-ev.png)



```
<Rule name="DCSync">
    	<InterfaceUUID>e3514235-4b06-11d1-ab04-00c04fc2dcd2</InterfaceUUID>
  	<OpNum>3</OpNum>
</Rule>
```




# Conclusion

With new attacks coming out daily, we hope to continuously add new detections and continue our research into Windows internals. Our next goal is to try and forward these logs to Elastic to be able to search the logs using their dashboard.

We hope you find this useful and can use this to detect any malicious behavior :)

Some future detections that might be possible are RemoteMonologue by @3lp4tr0n, Certipy, and CVE-2025-33073 
(We already have the RPC functions and interfaces that are used; we just need to continue testing our detections and refining the alerts.)  



# References 

https://learn.microsoft.com/en-us/windows/win32/midl/com-dcom-and-type-libraries

https://learn.microsoft.com/en-us/windows/win32/learnwin32/what-is-a-com-interface-

https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm

https://blog.es3n1n.eu/posts/how-i-ruined-my-vacation/

https://deepwiki.com/es3n1n/defendnot

https://www.akamai.com/blog/security-research/rpc-toolkit-fantastic-interfaces-how-to-find

https://www.ibm.com/think/news/fileless-lateral-movement-trapped-com-objects

https://www.kali.org/tools/impacket/

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410

https://gist.github.com/enigma0x3/092da9f249499391adffe2c46abfa1a1#file-rpc_dump_august-txt-L336

https://github.com/topotam/PetitPotam

