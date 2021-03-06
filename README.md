# Kaseya-CheckandMitigate
Truesec CSIRT team is releasing a script to help victims and responders of the Kaseya ransomware attack to identify and mitigate affected systems. 

This tool is intended to be used on end systems running a Kaseya Agent, not on a Kaseya VSA server.

We cover details around the attack in our blog post available at: https://blog.truesec.com/2021/07/04/kaseya-supply-chain-attack-targeting-msps-to-deliver-revil-ransomware/

# How to Use
1. Start PowerShell.exe or Cmd.exe as Administrator
2. Navigate to the location of the script
3. Execute: Powershell.exe -executionpolicy bypass -file .\Kaseya-CheckandMitigate.ps1

# Description
The tool will check for known Indicators of Compromise and when applicable, remove files or stop processes. 

- The BlackLivesMatter registry key will not be removed as it contains decryption related information.
- The hash exclusions in Kaseya's script are not included in this script.

Any feedback is appreciated!

# Disclaimer
This tool should be used by professionals with the ability to determine both potential impact and outcome of an execution. The script does not proclaim a system as "safe" or "secure". 
It checks for the predefined parameters as detailed in the script and nothing more. The script will also stop running processes if its executionpath points towards a known indicator of compromise as defined within the script.

# Compatibility
The script is designed to be compatible on all Windows PowerShell versions between 2 and 5. It has currently been tested on the following versions:
- Windows 10, PowerShell version 5.1
- Windows Server 2019, PowerShell version 5.1
- Windows Server 2016, PowerShell version 5.1
- Windows Server 2012 R2, PowerShell 4.0 - See Known Issues section
- Windows Server 2012, PowerShell 3.0
- Windows Server 2008 R2 with SP1, PowerShell 2.0
- Windows Server 2008 R2, PowerShell 2.0

# Known Issues
PowerShell 4.0 have a few builds that have a confirmed bug with Start-Transcript, this was noticed during testing of Windows Server 2012 R2 where the rename of the Transcript file did not reflect the indications found.

- Issue verified on Windows Server 2012 R2, PowerShell Version 4.0 Build 6.3.9600.17400

Work around: Update PowerShell to a later build or major version.
- Work around verified on Windows Server 2012 R2, PowerShell Version 4.0 Build 6.3.9600.18773

# TODO 
- [ ] Test more operating system and PowerShell versions
- [ ] Change hardcoded path "C:\" to $env:SystemDrive
- [ ] Add checks for malicious PowerShell execution in local event log
- [ ] Add checks for malicious execution in AgentMon log
- [ ] Implement option to only check for indicators of compromise, but not remove anything
- [ ] Implement log and report function