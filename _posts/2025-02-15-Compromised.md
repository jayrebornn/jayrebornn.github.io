---  
layout: post
title: Compromised
subtitle: HTB Write-up
thumbnail-img: assets/img/compromised.png
share-img: assets/img/compromised.png
tags: [HackTheBox, Sherlock, Compromised, SOC, Malware Analysis]
author: Jacob Acuna 
---

# Overview

Sherlock Scenario: Our SOC team detected suspicious activity in Network Traffic, the machine has been compromised and company information that should not have been there has now been stolen – it’s up to you to figure out what has happened and what data has been taken.

Objective: This challenge gave us a PCAP file and made us use OSINT to gather intelligence on the malware affecting our system.

# Tasks

Q1. What is the IP address used for initial access?

For this question, I opened wireshark and saw a lot of DNS traffic. But the first thing I did was see if we were able to export any HTTP objects and we were. Looking at the list we see an IP address that isn’t internal or a common scheme and has a weird filename. Investigating further we see that virus total recognizes this IP as malicious. 

![image](https://github.com/user-attachments/assets/fc4a804f-6f0e-46bb-8a02-c4907f6b5f2c)

VirusTotal is a great tool to check if any hostnames, domains, or hashes are malicious. And indeed this is the IP address used for initial access. 

![image](https://github.com/user-attachments/assets/51b4faeb-9109-4d47-b173-087ebf420e41)

  162.252.172.54

Q2. What is the SHA256 hash of the malware?
 For this question, we should go ahead and export this object and navigate 
to it in our terminal. We should be doing this in a virtual machine as can potentially inject our machine. Once the object has been exported we are able to run the following command to compute the hash of the file 
‘sha256sum 6ctf5JL’

![image](https://github.com/user-attachments/assets/b7fc150f-b3de-4f46-bd9c-6efebf25a144)


  9b8ffdc8ba2b2caa485cca56a82b2dcbd251f65fb30bc88f0ac3da6704e4d3c6

Q3.  What is the Family label of the malware?
For this question, we can navigate to virus total and see that it has labels for the malware. 

![image](https://github.com/user-attachments/assets/d3fd6c8b-5aee-40af-aa0f-4e6ba286d7ad)
 
  Pikabot

Q4. When was the malware first seen in the wild (UTC)?
For this challenge we can navigate to the Details tab on VirusTotal, and when we scroll down we can see the first seen in the wild. 

![image](https://github.com/user-attachments/assets/433f7c77-221f-4dcc-bc7e-4e1ba86f75ad)

  2023-05-19 14:01:21

Q5. The malware used HTTPS traffic with a self-signed certificate. What are the ports, from smallest to largest?
We can use the following command to find ssl certificates ‘ssl.handshake.type==11 and ip.dst==172.16.1.191’. We then have to naviagate the packet and we can find the ports used. 
 
![image](https://github.com/user-attachments/assets/2e60de51-9504-4b3d-b41e-10e9293a4817)

![image](https://github.com/user-attachments/assets/2d2785b3-5f7f-4702-8684-c220ed6e61ed)

![image](https://github.com/user-attachments/assets/bcc5652a-4ce0-4450-a7f1-49e616b18efb)

![image](https://github.com/user-attachments/assets/8f194684-c0f6-448b-9aeb-4308880e5e16)

Q6. What is the id-at-localityName of the self-signed certificate associated with the first malicious IP?
We find the packet that was sent right after the certificate request, and if we navigate to the bottom we can find the id-at-localityName.  

![image](https://github.com/user-attachments/assets/35a1af66-1dd6-433b-bdaa-32d68adee85e)

  Pyopneumopericardium

Q7. What is the notBefore time(UTC) for this self-signed certificate?
For this question we can use the same packet and go to notBefore under validity.  

![image](https://github.com/user-attachments/assets/7ccbcee9-6a05-490f-9391-bd3ef8ddd2d7)

  2023-05-14 08:36:52

Q8. What was the domain used for tunneling?
For this question, we can filter for DNS and search for any suspicious domain names and we see steasteel.net

![image](https://github.com/user-attachments/assets/b84f5a43-59fd-49dd-8e28-841ff07cdcce)

  steasteel.net

# Conclusion

![image](https://github.com/user-attachments/assets/9d980143-0051-4006-aa5b-8c1a80b3c077)

I had a lot of fun doing this challenge. It reminded me of when I worked as a SOC intern and had to perform OSINT on the different suspicious files we found on devices. Although tools like Virus Total are not a definitive answer as to whether or not a file is malicious, it is a good start. In my malware analysis class, we are currently learning about fuzzy hashing, which is an interesting topic when considering threat intelligence and adversaries trying to evade detection by changing a single letter and completely changing the entire hash.

Fuzzy hashing sections a file up and hashes each section, then compares them to other known hash segments and grades a score on similarity. A higher similarity score means there are more file segments that match the known malicious one, and it is likely to be the same file with little changes.  
