# Kaseya-CheckandMitigate
Truesec CSIRT team is releasing a script to help victims and responders of the Kaseya ransomware attack to identify and mitigate affected systems.

# Description
The tool will check for known Indicators of Compromise and when applicable, remove files or stop processes. The BlackLivesMatter registry key will not be removed as it contains decryption related information.
The hash exclusions in Kaseya's script are not included in this script.

Any feedback is appreciated!

# Disclaimer
This tool should be used by professional with the ability to determine the outcome of an execution. The script does not proclaim a system as "safe" or "secure". 
It checks for the predefined parameters as detailed in the script and nothing more.

# Compatibility
The tool has been tested on the following versions:
- Windows 10, PowerShell version 2 and 5
- Windows Server 2012 R2 PowerShell version 2 and 4

# TODO 
- [ ] Test more operating system and PowerShell versions
- [ ] Change hardcoded path "C:\" to $env:SystemDrive
- [ ] Implement option to only check for indicators of compromise, but not remove anything
