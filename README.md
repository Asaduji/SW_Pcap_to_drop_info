# SW Pcap to drop info
Dump item drop infos from SoulWorker runs from .pcapng captures, this can be used to generate drop tables

# Installation
Download the latest release from https://github.com/Asaduji/SW_Pcap_to_drop_info/releases/latest then put in the same directory the SWCrypt.dll that can be found here: https://github.com/AFNGP/SoulMeter/releases/latest
<br>
<br>
The reason why I don't include that dll is because it's closed source and packed with Themida, I have no control over it and I don't want to upload it by myself.

# Usage
Drop the .pcapng file into the .exe, it will generate the dump as .json in the same directory as the .pcapng file
You must whitelist the IPs by adding them to the IpWhitelist.txt file, packets received to an IP not present there will be ignored

# Compilation
To compile just open the solution in Visual Studio 2022 and click "Compile", you can also compile the SWCryptWrapper.dll from its project solution the same way.
