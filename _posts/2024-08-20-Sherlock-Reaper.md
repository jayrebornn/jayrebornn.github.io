---  
layout: post
title: Reaper
subtitle: HTB Write-up
thumbnail-img: assets/img/Reaper.png
share-img: assets/img/Reaper.png
tags: [HackTheBox, Sherlock, Reaper]
author: Jacob Acuna 
---

# Overview

  Sherlock Scenario: Our SIEM alerted us to a suspicious logon event which needs to be looked at immediately. The alert details were that the IP Address and the Source Workstation name were a mismatch.You are provided a network capture and event logs from the surrounding time around the incident timeframe. Correlate the given evidence and report back to your SOC Manager.

  Objective: This challenge has given us two sources to find our flags a .pcap file and .evtx file. Both of these are important when tracking malicious activity on your system. 

# Tasks

-Task 1: What is the IP Address for Forela-WKstn001?

![image](https://github.com/user-attachments/assets/c1d6add7-bbf9-49f2-9c52-fc2400660b79)

In this first challenge, we will use our Wireshark .pcap file. The first thing we do is search for any nbns (NetBIOS Name Service) traffic, this will allow us to see which IP address is requesting a name on our network. 

     172.17.79.129

-Task 2: What is the IP Address for Forela-Wkstn002? 

![image](https://github.com/user-attachments/assets/0489b166-4c06-456e-b10e-a5e7f24ff7aa)

The second challenge is very similar to the first where we use the Wireshark .pcap file and search for nbns traffic.

    172.17.79.136

-Task 3: Which user accounts hash was stolen by attacker? 

For this challenge, there were only a limited amount of events so it was possible to just go through each one, but I used the XML query below to only return events with the ID of 4624. If you don't know already that means the user was able to successfully logon. 

![image](https://github.com/user-attachments/assets/45c5f54a-ef7d-43a9-a558-6331505d15c5)

After having all the events with an ID in 4624 I used my arrow keys to go through each one and see if I can see anything unusual. After going through I found a NULL SID, blank logon ID, and a single logon with no elevated token, so I investigated it and the user account was arthur kyle. Another sign that this was our malicious actor was that the account was authenticated using NTLM whereas the rest were Kerberos. 

![image](https://github.com/user-attachments/assets/ce4baca9-dd75-412f-977c-6bc029871834)

     arthur kyle

Task 4: What is the IP Address of Unknown Device used by the attacker to intercept credentials? 

![image](https://github.com/user-attachments/assets/b3645bc6-6a99-412a-b85e-ee1ee33dcc70)

In this example we able to use the same event, as the source network address is given. 

    172.17.79.135 

Task 5: What was the file share navigated by the victim user account? 

![image](https://github.com/user-attachments/assets/e69adccc-3a76-44d0-ba23-a5d1421a0fb6)

In this challenge we head back to Wireshark and filter for smb2 traffic and we furthered this search by searching for the string Bad_Network_Name. After doing this we are able to see the connection request to our file share. 
  -Server Message Block v2 (smb2) and this is a network protocol that allows clients to access files and other things 

    \\DC01\Trip

Task 6: What is the source port used to logon to target workstation using the compromised account? 

![image](https://github.com/user-attachments/assets/6711a1aa-f039-40fa-a8d0-be8208d6314b)

In this task we are asked to find the source port for the malicious connection, and for this we can go back to the orginal logon event and see that it is under our network address. 

    40252

Task 7: What is the Logon ID for the malicious session? 

![image](https://github.com/user-attachments/assets/2c5ac4a7-e2ce-492a-a433-636db2755f82)

We will once again use the original logon event for this task. IN this event under the 'New Logon' we are able to see the Logon ID.

    0x64A799

Task 8: The detection was based on the mismatch of host name and the assigned IP Address. What is the workstation name and the source IP Address from which the malicious logon occur?

![image](https://github.com/user-attachments/assets/ad13c509-f112-4c67-a89e-2d23b6ca4781)

Using the same event, we are able to see the workstation name, source IP Address, and Source port. 

    FORELA-WKSTN002, 172.17.79.135

Task 9: When did the malicious logon happened. Please make sure the time stamp is in UTC

![image](https://github.com/user-attachments/assets/f45ce6a5-55de-491c-b6ee-bfb1c63dba2b)

For this task I kept getting it wrong because I was using the logged time and date as the flag, but eventually I switched over to the details section of the event and expanded SYSTEM, and from here I was able to see the system time from when the event actually happened. 

    2024-07-31 04:55:16

Task 10: What is the share Name accessed as part of the authentication process by the malicious tool used by the attacker? 

![image](https://github.com/user-attachments/assets/cd2f3c86-f40e-44a3-a03f-147caebfeb25)

For this challenge, I cleared my XML query to see all the events. After doing this I looked through them and saw that there was only one Event with an ID of 5140 which is when a File share is accessed. If there where more events that made scrolling through we could use queries to show any event with an ID of 5140 using the same format as before. But after opening that event we see the share name that was accessed. 

    \\*\IPC$

# Conclusion 

![image](https://github.com/user-attachments/assets/634ff2ad-e53c-4e95-8426-e4e1d29b82cf)

 Overall this was super fun being my first Sherlock I was able to learn so much more and apply my past experiences. I am currently going through the HTB CDSA pathway, and our current module was over Windows Event Viewer so it was super fun to apply what im learning to a challenge like this. I have done some CTF's in the past and the Wireshark ones were always my favorite so it fun bringing what I knew to this challenge and learning more. After this Sherlock it showed how important the windows event viewer is and how it can be used to track malicious activity. 
    
