---  
layout: post
title: Noxious
subtitle: HTB Write-up
thumbnail-img: assets/img/Noxious.png
share-img: assets/img/Noxious.png
tags: [HackTheBox, Sherlock, Noxious, SOC]
author: Jacob Acuna 
---

# Overview

  Sherlock Scenario: The IDS device alerted us to a possible rogue device in the internal Active Directory network. The Intrusion Detection System also indicated signs of LLMNR traffic, which is unusual. It is suspected that an LLMNR poisoning attack occurred. The LLMNR traffic was directed towards Forela-WKstn002, which has the IP address 172.17.79.136. A limited packet capture from the surrounding time is provided to you, our Network Forensics expert. Since this occurred in the Active Directory VLAN, it is suggested that we perform network threat hunting with the Active Directory attack vector in mind, specifically focusing on LLMNR poisoning.

  Objective: This challenge has given us a .pcap file, we will use this and our knowledge of LLMNR to understand the attack on our system. 

  LLMNR Overview: What is LLMNR? Link-Local Multicast Name Resolution (LLMNR) are used to resolve hostnames to UP addresses on local networks when the full qualified domain name (FQDN) resolution fails. 

The attack process for an LLMNR attack includes multiple steps:

1.  First, the victim device sends a name resolution query for a mistyped hostname. 
2. Then the DNS then fails to resolve the mistyped hostname
3. The victim device sends a name resolution query for the mistyped hostname using LLMNR/Net Bios Name Service (NBT-NS). 
4. Finally, the attacker's host responded to the LLMNR (UDP 5355) traffic pretending to know the identity of the requested host.

# Tasks

-Task 1: Its suspected by the security team that there was a rogue device in Forela's internal network running responder tool to perform an LLMNR Poisoning attack. Please find the malicious IP Address of the machine.


First, we filter for llmnr, we then go through and try to locate any suspicious-looking requests. That is when we see 172.17.19.135

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/c76c8e23-fc1b-4e82-bb55-47f217268329/image.png)

We can also filter for udp.port == 5355 the port which llmnr activity occurs on and locate the IP address that is different 

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/9d8d90cc-a534-4957-af6f-a5e62368cef4/image.png)

Answer: `172.17.79.135`

-Task 2: What is the hostname of the rogue machine?

Next, we are tasked with looking for the hostname of the malicious device. Given the IP address we should look for DHCP requests this will tell us the hostname. We can use the following filter in Wireshark 
`ip.addr == 172.17.79.135 && dhcp` 

we can see that there are three different packets, one of these stands out. The DHCP request packet, once we open it and look inside we can see the hostname.

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/34011fea-4148-4a59-9796-f9ddfafb570f/image.png)

Answer: `kali`

-Task 3: Now we need to confirm whether the attacker captured the user's hash and it is crackable!! What is the username whose hash was captured?

Filtering for smb2 we can see NTLMSSP Negotiate, this means that the hash was successfully able to be extracted. We can then see the user name in the NTLMSSP_AUTH packet as:


![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/524f1aa3-5cae-4f58-9a67-ab00252af6b9/image.png)

Answer: `john.deacon`

-Task 4: In NTLM traffic we can see that the victim credentials were relayed multiple times to the attacker's machine. When were the hashes captured the First time?

For this challenge we had to change the time format in Wireshark to make detection easier, we can use the view tab -> time display format -> UTC Date and Time. We can then scroll to the top and see the first time the hash was used 

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/262f67d4-f6fe-4637-ad93-8e60b541c3c9/image.png)

Answer: `2024-06-24 06:18:30`

-Task 5: What was the typo made by the victim when navigating to the file share that caused his credentials to be leaked?

We can see the typo the victim made by searching for llmnr in Wireshark and scrolling until we see any weird spelling mistakes. 

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/67d3bb44-8a74-4bd6-8d3b-421bcbbe4d20/image.png)

Answer: `DC001`


-Task 6: To get the actual credentials of the victim user we need to stitch together multiple values from the ntlm negotiation packets. What is the NTLM server challenge value?

For this challenge we had to locate a packet that contained the challenge value, once found we went to the packet and sifted through it until we found the challenge value. We can use the following method 
 SMB2 (Server Message Block ProtocolVersion 2) -> Session Setup Response (0x1) -> Security Blob -> GSS-API Generic -> SimpleProtected Negotiation -> negTokenTarg -> NTLM Secure Service Provider -> NTLM Server Challenge.

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/cc56339a-9bdb-461b-bd73-c6428b88e0a6/image.png)

Answer: `601019d191f054f1`

-Task 7: Now doing something similar find the NTProofStr value.

We have to follow the same methodology and find the NTProofStr value 

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/31fce284-1144-4d21-8b46-445fd430907b/image.png)

Answer: `c0cc803a6d9fb5a9082253a04dbd4cd4`

-Task 8: To test the password complexity, try recovering the password from the information found from packet capture. This is a crucial step as this way we can find whether the attacker was able to crack this and how quickly.

To do this we had to create a txt file with the information that we gathered and use hashcat to crack the password. 
User::Domain:ServerChallenge:NTProofStr:NTLMv2Response (Without the first 16 bytes \ 32 characters) 

This means that we are missing one more piece of value the NTLMv2Response but this can be found in the same place as the NTProofStr. 
![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/474ed1dd-902e-4e12-a22d-f3f7a12840b2/image.png)

Now with the last piece of information, we can craft our .txt file. 
![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/64ed3c9b-c6fb-405d-af53-4bed348a56e3/image.png)

Once this is done we can use hashcat and see if we can crack the password. 
`hashcat -a0 -m5600 noxious.txt /usr/share/wordlists/rockyou.txt`

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/059db279-80d8-4a04-ad17-e2b58a580086/image.png) 

Finally, we get our cracked password: 
Answer: `NotMyPassword0k?`

-Task 9: Just to get more context surrounding the incident, what is the actual file share that the victim was trying to navigate to?

To find this we can filter for smb2 and look until we see any non-default file paths for a share. 

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/1e6ec9bc-9e2c-4fab-9fa0-5a3eba28164e/image.png)

Answer:`\\DC01\DC-Confidential`

# Conclusion 

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/54a442f6-2e57-4f15-9a19-04e63ae84bed/43654884-c7ab-4f0a-aa35-529d79314d76/image.png)

Overall, I think this was a super fun Sherlock that went into LLMNR poisoning. This is my first Sherlock after finishing CDSA and I enjoyed the Wireshark detective work that went into this challenge. The CDSA pathway on Responder like attacks with LLMNR and NBT-NS which was useful in this challnege. 
