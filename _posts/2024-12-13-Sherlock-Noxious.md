---  
layout: post
title: Noxious
subtitle: HTB Write-up
thumbnail-img: assets/img/Noxious.pdf
share-img: assets/img/Noxious.pdf
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


Task 1: Its suspected by the security team that there was a rogue device in Forela's internal network running responder tool to perform an LLMNR Poisoning attack. Please find the malicious IP Address of the machine.


First, we filter for llmnr, we then go through and try to locate any suspicious-looking requests. That is when we see 172.17.19.135

![image](https://github.com/user-attachments/assets/f58a2659-d9f5-44bc-b0f6-a5ac78a929c3)


We can also filter for udp.port == 5355 the port which llmnr activity occurs on and locate the IP address that is different 

![image](https://github.com/user-attachments/assets/9a2824f0-8a59-45a9-b50b-2f8b4b04e965)

Answer: `172.17.79.135`


Task 2: What is the hostname of the rogue machine?

Next, we are tasked with looking for the hostname of the malicious device. Given the IP address we should look for DHCP requests this will tell us the hostname. We can use the following filter in Wireshark 
`ip.addr == 172.17.79.135 && dhcp` 

we can see that there are three different packets, one of these stands out. The DHCP request packet, once we open it and look inside we can see the hostname.

![image](https://github.com/user-attachments/assets/aab2e6fb-5cbe-46ba-9c62-fb9aa74ebe42)

Answer: `kali`


Task 3: Now we need to confirm whether the attacker captured the user's hash and it is crackable!! What is the username whose hash was captured?

Filtering for smb2 we can see NTLMSSP Negotiate, this means that the hash was successfully able to be extracted. We can then see the user name in the NTLMSSP_AUTH packet as:


![image](https://github.com/user-attachments/assets/2fca68d9-18ad-45ee-8220-13ad1ca295cc)

Answer: `john.deacon`


Task 4: In NTLM traffic we can see that the victim credentials were relayed multiple times to the attacker's machine. When were the hashes captured the First time?

For this challenge we had to change the time format in Wireshark to make detection easier, we can use the view tab -> time display format -> UTC Date and Time. We can then scroll to the top and see the first time the hash was used 

![image](https://github.com/user-attachments/assets/e1ed1455-57e1-436d-afc8-cb5c4d83547b)

Answer: `2024-06-24 06:18:30`


Task 5: What was the typo made by the victim when navigating to the file share that caused his credentials to be leaked?

We can see the typo the victim made by searching for llmnr in Wireshark and scrolling until we see any weird spelling mistakes. 

![image](https://github.com/user-attachments/assets/1d85375b-6d05-413c-a4d8-53817ec11c41)

Answer: `DC001`



Task 6: To get the actual credentials of the victim user we need to stitch together multiple values from the ntlm negotiation packets. What is the NTLM server challenge value?

For this challenge we had to locate a packet that contained the challenge value, once found we went to the packet and sifted through it until we found the challenge value. We can use the following method 
 SMB2 (Server Message Block ProtocolVersion 2) -> Session Setup Response (0x1) -> Security Blob -> GSS-API Generic -> SimpleProtected Negotiation -> negTokenTarg -> NTLM Secure Service Provider -> NTLM Server Challenge.

![image](https://github.com/user-attachments/assets/e7077de4-9263-49fc-bf15-8714d4b13972)

Answer: `601019d191f054f1`


Task 7: Now doing something similar find the NTProofStr value.

We have to follow the same methodology and find the NTProofStr value 

![image](https://github.com/user-attachments/assets/b7f2e823-294d-4553-94e4-995a6c9ac8b6)

Answer: `c0cc803a6d9fb5a9082253a04dbd4cd4`


Task 8: To test the password complexity, try recovering the password from the information found from packet capture. This is a crucial step as this way we can find whether the attacker was able to crack this and how quickly.

To do this we had to create a txt file with the information that we gathered and use hashcat to crack the password. 
User::Domain:ServerChallenge:NTProofStr:NTLMv2Response (Without the first 16 bytes \ 32 characters) 

This means that we are missing one more piece of value the NTLMv2Response but this can be found in the same place as the NTProofStr. 
![image](https://github.com/user-attachments/assets/cc4dc9fa-ba13-4625-abf8-2cec124a6286)

Now with the last piece of information, we can craft our .txt file. 
![image](https://github.com/user-attachments/assets/0a1958be-0c64-4e7a-bbb4-e725e4bbba79)

Once this is done we can use hashcat and see if we can crack the password. 
`hashcat -a0 -m5600 noxious.txt /usr/share/wordlists/rockyou.txt`

![image](https://github.com/user-attachments/assets/a5cd4976-479a-439f-a408-80060896bde6)

Finally, we get our cracked password: 
Answer: `NotMyPassword0k?`


Task 9: Just to get more context surrounding the incident, what is the actual file share that the victim was trying to navigate to?

To find this we can filter for smb2 and look until we see any non-default file paths for a share. 

![image](https://github.com/user-attachments/assets/931d53f9-ef07-486f-8ca8-41db34d6bd6a)

Answer:`\\DC01\DC-Confidential`

# Conclusion 

![image](https://github.com/user-attachments/assets/a778b92f-8bc6-4e7f-bac1-641f5b26154d)

Overall, I think this was a super fun Sherlock that went into LLMNR poisoning. This is my first Sherlock after finishing CDSA and I enjoyed the Wireshark detective work that went into this challenge. The CDSA pathway on Responder like attacks with LLMNR and NBT-NS which was useful in this challnege. 
