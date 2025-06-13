---
layout: post
title: COMmanding COM Telemetry  - A look into RPC calls
thumbnail-img: /assets/img/commander/COMmander.png
share-img: /assets/img/commander/COMmander.png
tags: [COM, DCOM, RPC, Windows Internals, Detections]
---

# Introduction 

This is some research into RPC and detecting COM and DCOM attacks that @hullabrian and I worked on during our free time. This is something that can hopefully make detection
on advanced attacks more easy. 

Over the past year, we have seen an increase in Component Object Model (COM) and Distributed Component Object Model (DCOM) attacks. 
These protocols use Remote Procedure Calls (RPC), which allow communication between two distributed component objects. Within these RPC calls, there are RPC interfaces; these are
the methods within the object that define the capabilities of the COM object and allow us to get an idea of the actions being performed. Following these interfaces 
allow us to track any malicious behavior and create detections based on the activiy. 

There are not many ways to follow COM and DCOM based attacks as no tools really track RPC activity. So we wanted to find a new way to detect these attacks as a way to continue to monitor communication between 
systems, and learn a little more about window internals. We won't go too much into the actual attacks and how they work, just the process of building the detections for our tool and potential IoC's within the RPC communication.
This is where our tool COMmander comes into play, it is based in C# and when run will start a Windows RPC ETW session and continue to monitor the traffic looking for specific rules and create alerts when traffic is met. 
There are two ways of using COMmander, either as a service that creates Windows Event Logs or as a command-line tool that alerts in the terminal.




- [Introduction](#introduction)
- [Installing COMmander](#COMmander)
- [Attacks](#attacks)
  - [DefendNot](#defendNot)
  - [ForsHops](#forshops)
  - [RemoteRegistry](#remoteRegistry)
  - [PetitPotam](#petitPotam)
  - [DCSync](#dcSync)
  - [CVE-2025-33073](#cve-2025-33073)
- [Conclusion](#conclusion)
- [References](#references)


# Installing COMmander

To start using COMmander Service, get the binary from the releases tab in the GitHub. Within the release there will be a setup binary that you can run that will add the binary to services and enable auto-start. After running in a privileged Power Shell environment you can see that the service is running and enabled on startup.
There is also a script that will stop the COMmander binary and remove it from your system. 

![image](/assets/img/commander/commander-service.png)

We can also check the resource utilization of COMmander in task manager, and see that it is not a resource intensive process.

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

There are a couple of GitHub pages that have a dump of RPC functions. In this case, we will use the one by `enigma0x3` all we need to do is search for our interface by either the name or UUID.

![image](/assets/img/commander/commander-dump.png)

We can then see that the function that was called in RPCMon `s_wscRegisterSecurityProduct` is assigned Opnum 13. An Opnum is essentially the interface function that the client is calling. 
Using these IoCs, we can now build our detection for COMmander. 

The format for the detections in COMmander is XML, so our custom detection for DefendNot will look like.

'<Rules>
	<Rule name="defendnot">
	<InterfaceUUID>06bba54a-be05-49f9-b0a0-30f790261023</InterfaceUUID>
	<OpNum>13</OpNum>
	<Endpoint></Endpoint>
</Rules>'

To test our detection, we want to make sure that the COMmander service is running. We can do this in the service application. 

Now we can execute the defendnot attack and then check our Event Logs to see if an alert is generated.

![image](/assets/img/commander/commander-attack.png)

Now checking our Event Logs we see that the attack was detected. 

![image](/assets/img/commander/commander-ev1.png)

If we expand the alert we will get additional information about the alert that can aid us in the investigation. 

![image](/assets/img/commander/commander-enrich.png)
