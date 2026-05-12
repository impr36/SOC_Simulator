# rules/__init__.py
from .powershell_rules import POWERSHELL_RULES
from .lolbin_rules import LOLBIN_RULES
from .ransomware_rules import RANSOMWARE_RULES
from .credential_rules import CREDENTIAL_RULES
from .persistence_rules import PERSISTENCE_RULES
from .recon_rules import RECON_RULES
from .lateral_movement_rules import LATERAL_MOVEMENT_RULES
from .defense_evasion_rules import DEFENSE_EVASION_RULES
from .c2_rules import C2_RULES

__all__ = [
    "POWERSHELL_RULES", "LOLBIN_RULES", "RANSOMWARE_RULES",
    "CREDENTIAL_RULES", "PERSISTENCE_RULES", "RECON_RULES",
    "LATERAL_MOVEMENT_RULES", "DEFENSE_EVASION_RULES", "C2_RULES"
]

WINDOWS_EVENT_RULES = {

    4624: {
        "name": "Successful Login",
        "severity": "LOW",
        "description": "Successful user authentication detected."
    },

    4625: {
        "name": "Multiple Failed Login Attempts",
        "severity": "HIGH",
        "description": "Multiple failed authentication attempts detected. Possible brute-force attack."
    },

    4634: {
        "name": "User Logoff",
        "severity": "LOW",
        "description": "User logged off from the system."
    },

    4648: {
        "name": "Explicit Credential Logon",
        "severity": "MEDIUM",
        "description": "Logon attempted using explicit credentials."
    },

    4672: {
        "name": "Administrative Privileges Assigned",
        "severity": "HIGH",
        "description": "Special administrative privileges assigned to a new logon session."
    },

    4688: {
        "name": "New Process Created",
        "severity": "MEDIUM",
        "description": "A new process was created on the endpoint."
    },

    4689: {
        "name": "Process Terminated",
        "severity": "LOW",
        "description": "A process was terminated."
    },

    4697: {
        "name": "Suspicious Service Installation",
        "severity": "HIGH",
        "description": "A new Windows service was installed. Possible persistence mechanism."
    },

    4698: {
        "name": "Scheduled Task Created",
        "severity": "HIGH",
        "description": "A scheduled task was created. Possible persistence behavior."
    },

    4699: {
        "name": "Scheduled Task Deleted",
        "severity": "MEDIUM",
        "description": "A scheduled task was deleted."
    },

    4700: {
        "name": "Scheduled Task Enabled",
        "severity": "LOW",
        "description": "A scheduled task was enabled."
    },

    4701: {
        "name": "Scheduled Task Disabled",
        "severity": "MEDIUM",
        "description": "A scheduled task was disabled."
    },

    4702: {
        "name": "Scheduled Task Updated",
        "severity": "HIGH",
        "description": "A scheduled task was modified."
    },

    4719: {
        "name": "System Audit Policy Changed",
        "severity": "HIGH",
        "description": "System audit policy settings were changed."
    },

    4720: {
        "name": "New User Account Created",
        "severity": "HIGH",
        "description": "A new local user account was created."
    },

    4722: {
        "name": "User Account Enabled",
        "severity": "MEDIUM",
        "description": "A user account was enabled."
    },

    4723: {
        "name": "Password Change Attempt",
        "severity": "MEDIUM",
        "description": "An attempt was made to change an account password."
    },

    4724: {
        "name": "Password Reset Attempt",
        "severity": "HIGH",
        "description": "An attempt was made to reset an account password."
    },

    4725: {
        "name": "User Account Disabled",
        "severity": "MEDIUM",
        "description": "A user account was disabled."
    },

    4726: {
        "name": "User Account Deleted",
        "severity": "HIGH",
        "description": "A user account was deleted."
    },

    4727: {
        "name": "Security Group Created",
        "severity": "MEDIUM",
        "description": "A security-enabled global group was created."
    },

    4728: {
        "name": "User Added To Privileged Group",
        "severity": "HIGH",
        "description": "User account added to privileged security group."
    },

    4729: {
        "name": "User Removed From Privileged Group",
        "severity": "MEDIUM",
        "description": "User removed from privileged security group."
    },

    4732: {
        "name": "Member Added To Local Group",
        "severity": "HIGH",
        "description": "A member was added to a local security group."
    },

    4733: {
        "name": "Member Removed From Local Group",
        "severity": "MEDIUM",
        "description": "A member was removed from a local security group."
    },

    4738: {
        "name": "User Account Changed",
        "severity": "MEDIUM",
        "description": "A user account was modified."
    },

    4740: {
        "name": "User Account Locked",
        "severity": "HIGH",
        "description": "A user account was locked out."
    },

    4767: {
        "name": "User Account Unlocked",
        "severity": "LOW",
        "description": "A locked user account was unlocked."
    },

    4771: {
        "name": "Kerberos Pre-authentication Failed",
        "severity": "HIGH",
        "description": "Kerberos pre-authentication failed. Possible password attack."
    },

    4776: {
        "name": "Credential Validation Attempt",
        "severity": "MEDIUM",
        "description": "Credential validation attempt detected."
    },

    4781: {
        "name": "Account Name Changed",
        "severity": "MEDIUM",
        "description": "User account name was changed."
    },

    4798: {
        "name": "Local Group Membership Enumerated",
        "severity": "MEDIUM",
        "description": "User local group membership was enumerated."
    },

    4799: {
        "name": "Security Group Membership Enumerated",
        "severity": "MEDIUM",
        "description": "Security-enabled local group membership was enumerated."
    },

    4800: {
        "name": "Workstation Locked",
        "severity": "LOW",
        "description": "The workstation was locked."
    },

    4801: {
        "name": "Workstation Unlocked",
        "severity": "LOW",
        "description": "The workstation was unlocked."
    },

    4946: {
        "name": "Firewall Rule Added",
        "severity": "HIGH",
        "description": "A Windows Firewall rule was added."
    },

    4947: {
        "name": "Firewall Rule Modified",
        "severity": "HIGH",
        "description": "A Windows Firewall rule was modified."
    },

    4948: {
        "name": "Firewall Rule Deleted",
        "severity": "HIGH",
        "description": "A Windows Firewall rule was deleted."
    },

    4950: {
        "name": "Firewall Setting Changed",
        "severity": "HIGH",
        "description": "Windows Firewall settings were changed."
    },

    5001: {
        "name": "Windows Defender Disabled",
        "severity": "HIGH",
        "description": "Windows Defender real-time protection was disabled."
    },

    5024: {
        "name": "Windows Firewall Service Started",
        "severity": "LOW",
        "description": "Windows Firewall service started successfully."
    },

    5025: {
        "name": "Windows Firewall Service Stopped",
        "severity": "HIGH",
        "description": "Windows Firewall service was stopped."
    },

    5031: {
        "name": "Application Blocked By Firewall",
        "severity": "MEDIUM",
        "description": "An application was blocked from accepting connections."
    },

    5038: {
        "name": "Code Integrity Check Failed",
        "severity": "HIGH",
        "description": "Code integrity verification failed."
    },

    5140: {
        "name": "Network Share Accessed",
        "severity": "LOW",
        "description": "A network share object was accessed."
    },

    5142: {
        "name": "Network Share Added",
        "severity": "MEDIUM",
        "description": "A network share was added."
    },

    5143: {
        "name": "Network Share Modified",
        "severity": "MEDIUM",
        "description": "A network share was modified."
    },

    5144: {
        "name": "Network Share Deleted",
        "severity": "MEDIUM",
        "description": "A network share was deleted."
    },

    5152: {
        "name": "Packet Dropped By Firewall",
        "severity": "MEDIUM",
        "description": "Windows Filtering Platform blocked a packet."
    },

    5156: {
        "name": "Connection Allowed",
        "severity": "LOW",
        "description": "Windows Filtering Platform allowed a connection."
    },

    5157: {
        "name": "Connection Blocked",
        "severity": "HIGH",
        "description": "Windows Filtering Platform blocked a connection."
    },

    5379: {
        "name": "Credential Manager Access",
        "severity": "HIGH",
        "description": "Credential Manager credentials were read."
    },

    5632: {
        "name": "Wireless Authentication",
        "severity": "LOW",
        "description": "Wireless network authentication succeeded."
    },

    5633: {
        "name": "Wireless Association",
        "severity": "LOW",
        "description": "Wireless network association succeeded."
    },

    6005: {
        "name": "Event Log Service Started",
        "severity": "LOW",
        "description": "Windows Event Log service started."
    },

    6006: {
        "name": "Event Log Service Stopped",
        "severity": "MEDIUM",
        "description": "Windows Event Log service stopped."
    },

    6008: {
        "name": "Unexpected Shutdown",
        "severity": "HIGH",
        "description": "The previous shutdown was unexpected."
    },

    7030: {
        "name": "Service Configuration Warning",
        "severity": "MEDIUM",
        "description": "Service marked as interactive service."
    },

    7034: {
        "name": "Service Crashed",
        "severity": "MEDIUM",
        "description": "A Windows service terminated unexpectedly."
    },

    7035: {
        "name": "Service Control Sent",
        "severity": "LOW",
        "description": "A service control command was sent."
    },

    7036: {
        "name": "Service State Changed",
        "severity": "LOW",
        "description": "A service changed its running state."
    },

    7040: {
        "name": "Service Startup Changed",
        "severity": "HIGH",
        "description": "Service startup type was modified."
    },

    7045: {
        "name": "Windows Service Created",
        "severity": "HIGH",
        "description": "A Windows service was created on the system."
    },

    8001: {
        "name": "AppLocker Policy Applied",
        "severity": "LOW",
        "description": "AppLocker policy was applied successfully."
    },

    8002: {
        "name": "AppLocker Policy Audit",
        "severity": "MEDIUM",
        "description": "Application would have been blocked by AppLocker."
    },

    8003: {
        "name": "Application Blocked By AppLocker",
        "severity": "HIGH",
        "description": "Application execution blocked by AppLocker."
    },

    8004: {
        "name": "Script Blocked By AppLocker",
        "severity": "HIGH",
        "description": "Script execution blocked by AppLocker."
    },

    1100: {
        "name": "Event Logging Service Shutdown",
        "severity": "HIGH",
        "description": "Windows Event Logging service shut down."
    },

    1102: {
        "name": "Security Log Cleared",
        "severity": "HIGH",
        "description": "Windows security logs were cleared. Possible anti-forensics activity."
    },

    1104: {
        "name": "Security Log Full",
        "severity": "MEDIUM",
        "description": "Windows security log is full."
    },

    1116: {
        "name": "Malware Detected",
        "severity": "HIGH",
        "description": "Windows Defender detected malware."
    },

    1117: {
        "name": "Malware Remediation",
        "severity": "MEDIUM",
        "description": "Windows Defender performed malware remediation."
    },

    1118: {
        "name": "Malware Action Failed",
        "severity": "HIGH",
        "description": "Malware remediation action failed."
    },

    1121: {
        "name": "Controlled Folder Access Blocked",
        "severity": "HIGH",
        "description": "Controlled folder access blocked unauthorized changes."
    },

    11707: {
        "name": "Application Installed",
        "severity": "MEDIUM",
        "description": "A new application installation completed."
    },

    11724: {
        "name": "Application Removed",
        "severity": "MEDIUM",
        "description": "An application was removed from the system."
    },

    4103: {
        "name": "PowerShell Command Executed",
        "severity": "HIGH",
        "description": "PowerShell command execution detected."
    },

    4104: {
        "name": "PowerShell Script Block Logged",
        "severity": "HIGH",
        "description": "PowerShell script block execution detected."
    },

    4105: {
        "name": "PowerShell Command Started",
        "severity": "MEDIUM",
        "description": "PowerShell command invocation started."
    },

    4106: {
        "name": "PowerShell Provider Started",
        "severity": "LOW",
        "description": "PowerShell provider lifecycle event detected."
    },

    1000: {
        "name": "Application Crash",
        "severity": "MEDIUM",
        "description": "An application crashed unexpectedly."
    },

    1001: {
        "name": "Application Hang",
        "severity": "LOW",
        "description": "Application stopped responding."
    },

    1002: {
        "name": "Application Recovery",
        "severity": "LOW",
        "description": "Application recovery operation completed."
    },

    1014: {
        "name": "DNS Resolution Failure",
        "severity": "MEDIUM",
        "description": "DNS name resolution failed."
    },

    2004: {
        "name": "Resource Exhaustion",
        "severity": "HIGH",
        "description": "System resource exhaustion detected."
    },

    3002: {
        "name": "IPsec Authentication Failure",
        "severity": "HIGH",
        "description": "IPsec authentication failure detected."
    },

    3005: {
        "name": "IPsec Security Association Failure",
        "severity": "HIGH",
        "description": "Failed to establish IPsec security association."
    },

    800: {
        "name": "BITS Job Created",
        "severity": "MEDIUM",
        "description": "BITS transfer job created. Possible malware download activity."
    },

    1024: {
        "name": "RDP Session Connected",
        "severity": "MEDIUM",
        "description": "Remote Desktop session established."
    },

    1025: {
        "name": "RDP Session Disconnected",
        "severity": "LOW",
        "description": "Remote Desktop session disconnected."
    },

    1149: {
        "name": "Remote Desktop Login",
        "severity": "HIGH",
        "description": "Remote Desktop Services user authentication succeeded."
    },

    21: {
        "name": "Remote Desktop Session Logon",
        "severity": "MEDIUM",
        "description": "Remote Desktop session logon detected."
    },

    22: {
        "name": "Shell Start Notification",
        "severity": "LOW",
        "description": "Windows shell started."
    },

    23: {
        "name": "Session Logoff",
        "severity": "LOW",
        "description": "User session logged off."
    },

    24: {
        "name": "Session Disconnect",
        "severity": "LOW",
        "description": "User session disconnected."
    },

    25: {
        "name": "Session Reconnect",
        "severity": "LOW",
        "description": "User session reconnected."
    },

    39: {
        "name": "Time Service Synchronization Failure",
        "severity": "MEDIUM",
        "description": "System time synchronization failed."
    },

    40: {
        "name": "Kernel Power Unexpected Shutdown",
        "severity": "HIGH",
        "description": "System rebooted unexpectedly."
    },

    55: {
        "name": "File System Corruption",
        "severity": "HIGH",
        "description": "File system corruption detected."
    },

    98: {
        "name": "TCP Port Exhaustion",
        "severity": "HIGH",
        "description": "TCP/IP failed due to port exhaustion."
    },

    129: {
        "name": "Disk Controller Reset",
        "severity": "MEDIUM",
        "description": "Disk controller reset detected."
    },

    153: {
        "name": "Disk IO Retry",
        "severity": "MEDIUM",
        "description": "Disk operation retried due to IO issue."
    },

        154: {
        "name": "Disk Controller Failure",
        "severity": "HIGH",
        "description": "Disk controller encountered a critical failure."
    },

    157: {
        "name": "Disk Removed Unexpectedly",
        "severity": "HIGH",
        "description": "A storage disk was unexpectedly removed from the system."
    },

    200: {
        "name": "Driver Load Failure",
        "severity": "HIGH",
        "description": "A device driver failed to load properly."
    },

    201: {
        "name": "Packet Loss Detected",
        "severity": "MEDIUM",
        "description": "Network packet loss detected."
    },

    202: {
        "name": "Network Adapter Failure",
        "severity": "HIGH",
        "description": "Network adapter stopped responding."
    },

    203: {
        "name": "DNS Client Timeout",
        "severity": "MEDIUM",
        "description": "DNS client request timed out."
    },

    214: {
        "name": "Driver Verification Failure",
        "severity": "HIGH",
        "description": "Unsigned or invalid driver verification failed."
    },

    219: {
        "name": "Driver Initialization Failure",
        "severity": "MEDIUM",
        "description": "A driver failed during initialization."
    },

    300: {
        "name": "Time Synchronization Issue",
        "severity": "LOW",
        "description": "System clock synchronization inconsistency detected."
    },

    301: {
        "name": "Certificate Validation Failure",
        "severity": "HIGH",
        "description": "Certificate validation failed."
    },

    302: {
        "name": "TLS Handshake Failure",
        "severity": "HIGH",
        "description": "TLS/SSL handshake failed unexpectedly."
    },

    303: {
        "name": "Certificate Revoked",
        "severity": "HIGH",
        "description": "A revoked certificate was used."
    },

    304: {
        "name": "Suspicious Certificate Usage",
        "severity": "HIGH",
        "description": "Potential misuse of digital certificate detected."
    },

    400: {
        "name": "PowerShell Engine Started",
        "severity": "LOW",
        "description": "PowerShell engine startup detected."
    },

    403: {
        "name": "PowerShell Engine Stopped",
        "severity": "LOW",
        "description": "PowerShell engine shutdown detected."
    },

    500: {
        "name": "Unauthorized File Access",
        "severity": "HIGH",
        "description": "Unauthorized access attempt to protected file detected."
    },

    501: {
        "name": "File Permission Modified",
        "severity": "HIGH",
        "description": "Critical file permissions were modified."
    },

    502: {
        "name": "Sensitive File Deleted",
        "severity": "HIGH",
        "description": "Sensitive system file was deleted."
    },

    503: {
        "name": "File Integrity Violation",
        "severity": "HIGH",
        "description": "File integrity monitoring detected unauthorized modification."
    },

    504: {
        "name": "Suspicious File Rename",
        "severity": "MEDIUM",
        "description": "Potential malware-related file rename operation detected."
    },

    600: {
        "name": "Remote Service Connection",
        "severity": "MEDIUM",
        "description": "Remote service connection established."
    },

    601: {
        "name": "SMB Session Established",
        "severity": "LOW",
        "description": "SMB network session established."
    },

    602: {
        "name": "SMB Authentication Failure",
        "severity": "HIGH",
        "description": "SMB authentication failure detected."
    },

    603: {
        "name": "Excessive SMB Connections",
        "severity": "HIGH",
        "description": "Large number of SMB connections detected."
    },

    700: {
        "name": "Service Start Failure",
        "severity": "HIGH",
        "description": "Critical service failed to start."
    },

    701: {
        "name": "Unexpected Service Stop",
        "severity": "HIGH",
        "description": "Critical service stopped unexpectedly."
    },

    702: {
        "name": "Service Restart Loop",
        "severity": "MEDIUM",
        "description": "Repeated service restart attempts detected."
    },

    703: {
        "name": "Unauthorized Service Modification",
        "severity": "HIGH",
        "description": "Service configuration modified without authorization."
    },

    704: {
        "name": "Malicious Driver Installed",
        "severity": "HIGH",
        "description": "Potential malicious driver installation detected."
    },

    705: {
        "name": "Kernel Module Loaded",
        "severity": "MEDIUM",
        "description": "Kernel module or driver loaded into memory."
    },

    706: {
        "name": "Kernel Module Unloaded",
        "severity": "MEDIUM",
        "description": "Kernel module or driver unloaded from memory."
    },

    707: {
        "name": "Service Privilege Escalation",
        "severity": "HIGH",
        "description": "Service attempted privilege escalation."
    },

    708: {
        "name": "Unauthorized Driver Load",
        "severity": "HIGH",
        "description": "Unauthorized driver loading activity detected."
    },

    709: {
        "name": "System Service Tampering",
        "severity": "HIGH",
        "description": "Potential tampering with core system service detected."
    },

    900: {
        "name": "DNS Zone Transfer Attempt",
        "severity": "HIGH",
        "description": "Possible unauthorized DNS zone transfer attempt detected."
    },

    901: {
        "name": "DNS Cache Poisoning Attempt",
        "severity": "HIGH",
        "description": "Potential DNS cache poisoning detected."
    },

    902: {
        "name": "Suspicious DNS Query",
        "severity": "MEDIUM",
        "description": "Suspicious or malformed DNS query observed."
    },

    903: {
        "name": "Excessive DNS Requests",
        "severity": "MEDIUM",
        "description": "High volume DNS requests detected."
    },

    904: {
        "name": "DNS Tunneling Suspected",
        "severity": "HIGH",
        "description": "Possible DNS tunneling activity detected."
    },

    1003: {
        "name": "Application Installation Failure",
        "severity": "LOW",
        "description": "Application installation failed."
    },

    1004: {
        "name": "Application Permission Escalation",
        "severity": "HIGH",
        "description": "Application attempted unauthorized privilege escalation."
    },

    1005: {
        "name": "Suspicious DLL Injection",
        "severity": "HIGH",
        "description": "Potential DLL injection attack detected."
    },

    1006: {
        "name": "Application Sandbox Escape",
        "severity": "HIGH",
        "description": "Application attempted sandbox escape."
    },

    1007: {
        "name": "Unauthorized Registry Access",
        "severity": "HIGH",
        "description": "Unauthorized registry access attempt detected."
    },

    1008: {
        "name": "Registry Persistence Added",
        "severity": "HIGH",
        "description": "Persistence mechanism added to Windows Registry."
    },

    1009: {
        "name": "Registry Key Deleted",
        "severity": "MEDIUM",
        "description": "Registry key deletion detected."
    },

    1010: {
        "name": "Registry Startup Modification",
        "severity": "HIGH",
        "description": "Startup registry entries modified."
    },

    1011: {
        "name": "Unauthorized COM Object Registration",
        "severity": "HIGH",
        "description": "Potential malicious COM object registration detected."
    },

    1012: {
        "name": "LSASS Access Attempt",
        "severity": "HIGH",
        "description": "Potential credential dumping attempt targeting LSASS."
    },

    1013: {
        "name": "Credential Dumping Suspected",
        "severity": "HIGH",
        "description": "Possible credential dumping activity detected."
    },

        1015: {
        "name": "DNS Spoofing Attempt",
        "severity": "HIGH",
        "description": "Potential DNS spoofing activity detected."
    },

    1016: {
        "name": "Unauthorized Scheduled Execution",
        "severity": "HIGH",
        "description": "Unauthorized scheduled execution mechanism detected."
    },

    1017: {
        "name": "Executable Downloaded",
        "severity": "MEDIUM",
        "description": "Executable file downloaded from remote source."
    },

    1018: {
        "name": "Suspicious Archive Extraction",
        "severity": "MEDIUM",
        "description": "Potential malicious archive extraction activity detected."
    },

    1019: {
        "name": "Encoded PowerShell Command",
        "severity": "HIGH",
        "description": "Base64 or obfuscated PowerShell command execution detected."
    },

    1020: {
        "name": "Suspicious Child Process",
        "severity": "HIGH",
        "description": "Unexpected child process spawned by trusted application."
    },

    1021: {
        "name": "Macro Execution Detected",
        "severity": "HIGH",
        "description": "Office macro execution detected."
    },

    1022: {
        "name": "Remote Thread Injection",
        "severity": "HIGH",
        "description": "Remote thread injection attempt detected."
    },

    1023: {
        "name": "Memory Injection Attempt",
        "severity": "HIGH",
        "description": "Suspicious memory injection behavior detected."
    },

    1026: {
        "name": "Clipboard Access Detected",
        "severity": "LOW",
        "description": "Application accessed system clipboard."
    },

    1027: {
        "name": "Keylogging Activity Suspected",
        "severity": "HIGH",
        "description": "Potential keylogging behavior detected."
    },

    1028: {
        "name": "Screen Capture Activity",
        "severity": "MEDIUM",
        "description": "Screen capture operation detected."
    },

    1029: {
        "name": "Persistence Via Startup Folder",
        "severity": "HIGH",
        "description": "Persistence mechanism added to startup folder."
    },

    1030: {
        "name": "Unauthorized Startup Entry",
        "severity": "HIGH",
        "description": "Unauthorized startup program registration detected."
    },

    1031: {
        "name": "Windows Defender Configuration Changed",
        "severity": "HIGH",
        "description": "Windows Defender configuration modified."
    },

    1032: {
        "name": "Antivirus Disabled",
        "severity": "HIGH",
        "description": "Antivirus protection disabled."
    },

    1033: {
        "name": "Tamper Protection Disabled",
        "severity": "HIGH",
        "description": "Windows tamper protection disabled."
    },

    1034: {
        "name": "Suspicious Driver Signature",
        "severity": "HIGH",
        "description": "Unsigned or suspicious driver signature detected."
    },

    1035: {
        "name": "Unauthorized Kernel Access",
        "severity": "HIGH",
        "description": "Potential unauthorized kernel memory access detected."
    },

    1036: {
        "name": "Token Manipulation Detected",
        "severity": "HIGH",
        "description": "Access token manipulation or impersonation detected."
    },

    1037: {
        "name": "Named Pipe Communication",
        "severity": "MEDIUM",
        "description": "Suspicious named pipe communication detected."
    },

    1038: {
        "name": "Suspicious WMI Activity",
        "severity": "HIGH",
        "description": "Potential malicious WMI execution detected."
    },

    1039: {
        "name": "Remote WMI Execution",
        "severity": "HIGH",
        "description": "Remote command execution via WMI detected."
    },

    1040: {
        "name": "PowerShell Remoting Session",
        "severity": "HIGH",
        "description": "PowerShell remoting session initiated."
    },

    1041: {
        "name": "Suspicious Script Interpreter",
        "severity": "HIGH",
        "description": "Unusual script interpreter execution detected."
    },

    1042: {
        "name": "Credential Access Attempt",
        "severity": "HIGH",
        "description": "Potential unauthorized credential access detected."
    },

    1043: {
        "name": "Shadow Copy Deletion",
        "severity": "HIGH",
        "description": "Volume shadow copies deleted. Possible ransomware behavior."
    },

    1044: {
        "name": "Ransomware Encryption Activity",
        "severity": "CRITICAL",
        "description": "Mass file encryption activity detected."
    },

    1045: {
        "name": "Mass File Rename Activity",
        "severity": "HIGH",
        "description": "Large number of file rename operations detected."
    },

    1046: {
        "name": "Suspicious SMB Enumeration",
        "severity": "MEDIUM",
        "description": "Potential SMB enumeration activity detected."
    },

    1047: {
        "name": "Network Share Enumeration",
        "severity": "MEDIUM",
        "description": "Network share enumeration activity observed."
    },

    1048: {
        "name": "Lateral Movement Suspected",
        "severity": "HIGH",
        "description": "Potential lateral movement activity detected."
    },

    1049: {
        "name": "Pass-the-Hash Attempt",
        "severity": "CRITICAL",
        "description": "Potential pass-the-hash authentication detected."
    },

    1050: {
        "name": "Golden Ticket Activity",
        "severity": "CRITICAL",
        "description": "Potential Kerberos Golden Ticket attack detected."
    },

    1051: {
        "name": "Silver Ticket Activity",
        "severity": "CRITICAL",
        "description": "Potential Kerberos Silver Ticket attack detected."
    },

    1052: {
        "name": "Kerberoasting Activity",
        "severity": "HIGH",
        "description": "Potential Kerberoasting attack detected."
    },

    1053: {
        "name": "AS-REP Roasting Activity",
        "severity": "HIGH",
        "description": "Potential AS-REP Roasting attack detected."
    },

    1054: {
        "name": "Unauthorized Remote Desktop Usage",
        "severity": "HIGH",
        "description": "Unauthorized Remote Desktop activity detected."
    },

    1055: {
        "name": "Remote Assistance Session",
        "severity": "MEDIUM",
        "description": "Remote Assistance session initiated."
    },

    1056: {
        "name": "SMB Relay Attack Suspected",
        "severity": "CRITICAL",
        "description": "Potential SMB relay attack detected."
    },

    1057: {
        "name": "ARP Spoofing Detected",
        "severity": "HIGH",
        "description": "Potential ARP spoofing activity detected."
    },

    1058: {
        "name": "Network Sniffing Activity",
        "severity": "HIGH",
        "description": "Potential packet sniffing activity detected."
    },

    1059: {
        "name": "Suspicious Proxy Usage",
        "severity": "MEDIUM",
        "description": "Unauthorized proxy or tunneling activity detected."
    },

    1060: {
        "name": "Reverse Shell Connection",
        "severity": "CRITICAL",
        "description": "Potential reverse shell connection detected."
    },

    1061: {
        "name": "Beaconing Traffic Detected",
        "severity": "HIGH",
        "description": "Periodic outbound beaconing behavior detected."
    },

    1062: {
        "name": "Suspicious External Connection",
        "severity": "HIGH",
        "description": "Connection established with suspicious external host."
    },

    1063: {
        "name": "Data Exfiltration Suspected",
        "severity": "CRITICAL",
        "description": "Potential large-scale outbound data transfer detected."
    },

    1064: {
        "name": "Cloud Storage Upload Activity",
        "severity": "MEDIUM",
        "description": "Large upload activity to cloud storage provider detected."
    },

    1065: {
        "name": "Unauthorized VPN Connection",
        "severity": "HIGH",
        "description": "Unauthorized VPN connection detected."
    },

    1066: {
        "name": "Tor Network Usage",
        "severity": "HIGH",
        "description": "Connection to Tor anonymity network detected."
    },

    1067: {
        "name": "Cryptocurrency Mining Activity",
        "severity": "HIGH",
        "description": "Potential cryptocurrency mining activity detected."
    },

    1068: {
        "name": "CPU Usage Spike",
        "severity": "MEDIUM",
        "description": "Abnormal CPU utilization detected."
    },

    1069: {
        "name": "Memory Consumption Spike",
        "severity": "MEDIUM",
        "description": "Abnormal memory usage detected."
    },

    1070: {
        "name": "Disk Usage Spike",
        "severity": "MEDIUM",
        "description": "Abnormal disk activity detected."
    },

    1071: {
        "name": "Suspicious Compression Utility",
        "severity": "MEDIUM",
        "description": "Compression utility used on sensitive files."
    },

    1072: {
        "name": "Unauthorized Backup Activity",
        "severity": "HIGH",
        "description": "Unauthorized backup or archival activity detected."
    },

    1073: {
        "name": "USB Device Connected",
        "severity": "LOW",
        "description": "USB storage device connected to system."
    },

    1074: {
        "name": "Unauthorized USB Access",
        "severity": "HIGH",
        "description": "Unauthorized USB device activity detected."
    },

    1075: {
        "name": "Removable Media Data Transfer",
        "severity": "MEDIUM",
        "description": "Large data transfer to removable media detected."
    },

        1076: {
        "name": "Boot Configuration Modified",
        "severity": "HIGH",
        "description": "System boot configuration was modified."
    },

    1077: {
        "name": "Secure Boot Disabled",
        "severity": "CRITICAL",
        "description": "Secure Boot protection was disabled."
    },

    1078: {
        "name": "UEFI Configuration Change",
        "severity": "HIGH",
        "description": "UEFI firmware configuration modified."
    },

    1079: {
        "name": "Unauthorized BIOS Access",
        "severity": "HIGH",
        "description": "Potential unauthorized BIOS or firmware access detected."
    },

    1080: {
        "name": "System Recovery Disabled",
        "severity": "HIGH",
        "description": "System recovery features were disabled."
    },

    1081: {
        "name": "Windows Recovery Environment Modified",
        "severity": "HIGH",
        "description": "Windows Recovery Environment settings modified."
    },

    1082: {
        "name": "System Restore Deleted",
        "severity": "HIGH",
        "description": "System restore points deleted."
    },

    1083: {
        "name": "Unauthorized Disk Encryption",
        "severity": "HIGH",
        "description": "Unauthorized disk encryption activity detected."
    },

    1084: {
        "name": "BitLocker Disabled",
        "severity": "HIGH",
        "description": "BitLocker disk encryption disabled."
    },

    1085: {
        "name": "BitLocker Recovery Key Access",
        "severity": "HIGH",
        "description": "BitLocker recovery key accessed."
    },

    1086: {
        "name": "Unauthorized Network Scan",
        "severity": "HIGH",
        "description": "Potential internal network scanning activity detected."
    },

    1087: {
        "name": "Port Sweep Detected",
        "severity": "HIGH",
        "description": "Sequential port scanning behavior detected."
    },

    1088: {
        "name": "Fast Port Scan",
        "severity": "HIGH",
        "description": "High-speed port scanning activity detected."
    },

    1089: {
        "name": "Stealth Scan Detected",
        "severity": "HIGH",
        "description": "Potential stealth scanning behavior detected."
    },

    1090: {
        "name": "Suspicious ICMP Activity",
        "severity": "MEDIUM",
        "description": "Abnormal ICMP traffic patterns detected."
    },

    1091: {
        "name": "Ping Sweep Activity",
        "severity": "MEDIUM",
        "description": "ICMP ping sweep across hosts detected."
    },

    1092: {
        "name": "Unauthorized SSH Connection",
        "severity": "HIGH",
        "description": "Unauthorized SSH connection attempt detected."
    },

    1093: {
        "name": "Repeated Authentication Failures",
        "severity": "HIGH",
        "description": "Multiple repeated authentication failures detected."
    },

    1094: {
        "name": "Credential Stuffing Activity",
        "severity": "CRITICAL",
        "description": "Credential stuffing attack behavior detected."
    },

    1095: {
        "name": "Password Spraying Attack",
        "severity": "CRITICAL",
        "description": "Password spraying attack activity detected."
    },

    1096: {
        "name": "Brute Force Attack",
        "severity": "CRITICAL",
        "description": "Brute-force authentication attack detected."
    },

    1097: {
        "name": "Unauthorized Account Enumeration",
        "severity": "HIGH",
        "description": "Potential account enumeration activity detected."
    },

    1098: {
        "name": "Suspicious LDAP Query",
        "severity": "HIGH",
        "description": "Suspicious LDAP enumeration query detected."
    },

    1099: {
        "name": "Active Directory Enumeration",
        "severity": "HIGH",
        "description": "Potential Active Directory enumeration detected."
    },

    1101: {
        "name": "Audit Log Tampering",
        "severity": "CRITICAL",
        "description": "Potential audit log tampering activity detected."
    },

    1103: {
        "name": "Security Logging Disabled",
        "severity": "CRITICAL",
        "description": "Security event logging disabled."
    },

    1105: {
        "name": "Event Log Forwarding Failure",
        "severity": "MEDIUM",
        "description": "Windows Event Forwarding failure detected."
    },

    1106: {
        "name": "Suspicious Event Log Access",
        "severity": "HIGH",
        "description": "Unauthorized access to Windows event logs detected."
    },

    1107: {
        "name": "Event Subscription Modification",
        "severity": "MEDIUM",
        "description": "Event subscription configuration modified."
    },

    1108: {
        "name": "Windows Event Collector Failure",
        "severity": "MEDIUM",
        "description": "Windows Event Collector service failure detected."
    },

    1109: {
        "name": "Log Retention Policy Changed",
        "severity": "HIGH",
        "description": "Security log retention policy modified."
    },

    1110: {
        "name": "Windows Defender Scan Disabled",
        "severity": "HIGH",
        "description": "Windows Defender scanning disabled."
    },

    1111: {
        "name": "Threat Detection Failure",
        "severity": "HIGH",
        "description": "Threat detection engine failed to process malware."
    },

    1112: {
        "name": "Threat Signature Update Failed",
        "severity": "MEDIUM",
        "description": "Security signature update failed."
    },

    1113: {
        "name": "Real-time Protection Disabled",
        "severity": "CRITICAL",
        "description": "Real-time malware protection disabled."
    },

    1114: {
        "name": "Cloud Protection Disabled",
        "severity": "HIGH",
        "description": "Cloud-delivered protection disabled."
    },

    1115: {
        "name": "Malware Quarantine Failure",
        "severity": "HIGH",
        "description": "Malware could not be quarantined."
    },

    1119: {
        "name": "Potentially Unwanted Application Detected",
        "severity": "MEDIUM",
        "description": "Potentially unwanted application detected by antivirus."
    },

    1120: {
        "name": "Threat Remediation Incomplete",
        "severity": "HIGH",
        "description": "Threat remediation process incomplete."
    },

    1122: {
        "name": "Controlled Folder Access Disabled",
        "severity": "HIGH",
        "description": "Controlled Folder Access protection disabled."
    },

    1123: {
        "name": "Unauthorized Application Exclusion",
        "severity": "HIGH",
        "description": "Application added to antivirus exclusion list."
    },

    1124: {
        "name": "Suspicious File Quarantined",
        "severity": "MEDIUM",
        "description": "Potentially malicious file quarantined."
    },

    1125: {
        "name": "Exploit Protection Triggered",
        "severity": "HIGH",
        "description": "Exploit protection blocked suspicious activity."
    },

    1126: {
        "name": "Unauthorized Security Policy Change",
        "severity": "CRITICAL",
        "description": "Critical security policy modified without authorization."
    },

    1127: {
        "name": "Security Configuration Rollback",
        "severity": "HIGH",
        "description": "Security configuration rollback detected."
    },

    1128: {
        "name": "Unauthorized Domain Trust Modification",
        "severity": "CRITICAL",
        "description": "Domain trust relationship modified unexpectedly."
    },

    1129: {
        "name": "Suspicious Kerberos Ticket Request",
        "severity": "HIGH",
        "description": "Abnormal Kerberos ticket request behavior detected."
    },

    1130: {
        "name": "Kerberos Ticket Replay",
        "severity": "CRITICAL",
        "description": "Potential Kerberos replay attack detected."
    },

    1131: {
        "name": "Unauthorized Group Policy Modification",
        "severity": "CRITICAL",
        "description": "Group Policy Object modified without authorization."
    },

    1132: {
        "name": "GPO Replication Failure",
        "severity": "MEDIUM",
        "description": "Group Policy replication issue detected."
    },

    1133: {
        "name": "Suspicious SYSVOL Access",
        "severity": "HIGH",
        "description": "Unauthorized access to SYSVOL share detected."
    },

    1134: {
        "name": "Domain Controller Replication Abuse",
        "severity": "CRITICAL",
        "description": "Potential DCSync or replication abuse detected."
    },

    1135: {
        "name": "Pass-the-Ticket Attack",
        "severity": "CRITICAL",
        "description": "Potential pass-the-ticket attack detected."
    },

    1136: {
        "name": "Unauthorized Certificate Enrollment",
        "severity": "HIGH",
        "description": "Suspicious certificate enrollment request detected."
    },

    1137: {
        "name": "Certificate Authority Modification",
        "severity": "CRITICAL",
        "description": "Certificate Authority configuration modified."
    },

    1138: {
        "name": "Suspicious Smart Card Authentication",
        "severity": "HIGH",
        "description": "Abnormal smart card authentication activity detected."
    },

    1139: {
        "name": "NTLM Relay Attack",
        "severity": "CRITICAL",
        "description": "Potential NTLM relay attack detected."
    },

    1140: {
        "name": "Unauthorized SAM Database Access",
        "severity": "CRITICAL",
        "description": "Unauthorized access to Security Account Manager database."
    },

    1141: {
        "name": "SAM Dump Attempt",
        "severity": "CRITICAL",
        "description": "Potential SAM credential dumping detected."
    },

    1142: {
        "name": "LSA Protection Disabled",
        "severity": "CRITICAL",
        "description": "Local Security Authority protection disabled."
    },

    1143: {
        "name": "Suspicious Security Package Loaded",
        "severity": "HIGH",
        "description": "Untrusted security package loaded into authentication process."
    },

    1144: {
        "name": "Unauthorized Winlogon Modification",
        "severity": "HIGH",
        "description": "Winlogon registry modification detected."
    },

    1145: {
        "name": "Credential Provider Injection",
        "severity": "HIGH",
        "description": "Potential credential provider tampering detected."
    },

    1146: {
        "name": "Unauthorized DLL Search Order Hijacking",
        "severity": "HIGH",
        "description": "Potential DLL search order hijacking detected."
    },

    1147: {
        "name": "Side-Loading DLL Detected",
        "severity": "HIGH",
        "description": "Suspicious DLL side-loading behavior detected."
    },

    1148: {
        "name": "COM Hijacking Activity",
        "severity": "HIGH",
        "description": "Potential COM object hijacking detected."
    },

    1150: {
        "name": "Unauthorized Scheduled Task Modification",
        "severity": "HIGH",
        "description": "Scheduled task configuration modified unexpectedly."
    },

    1151: {
        "name": "Task Scheduler Abuse",
        "severity": "HIGH",
        "description": "Potential abuse of Windows Task Scheduler detected."
    },

    1152: {
        "name": "Malicious Script Execution",
        "severity": "CRITICAL",
        "description": "Known malicious scripting behavior detected."
    },

    1153: {
        "name": "Encoded Script Execution",
        "severity": "HIGH",
        "description": "Encoded script execution activity detected."
    },

    1154: {
        "name": "Obfuscated Command Execution",
        "severity": "HIGH",
        "description": "Obfuscated command-line execution detected."
    },

    1155: {
        "name": "Suspicious Command Shell Spawn",
        "severity": "HIGH",
        "description": "Unexpected command shell spawned by application."
    },

    1156: {
        "name": "LOLBin Abuse Detected",
        "severity": "CRITICAL",
        "description": "Living-off-the-land binary abuse detected."
    },

    1157: {
        "name": "Certutil Abuse",
        "severity": "HIGH",
        "description": "Potential malicious use of certutil detected."
    },

    1158: {
        "name": "Bitsadmin Abuse",
        "severity": "HIGH",
        "description": "Potential malicious BITSAdmin usage detected."
    },

    1159: {
        "name": "MSHTA Execution",
        "severity": "HIGH",
        "description": "Potential malicious MSHTA execution detected."
    },

    1160: {
        "name": "Rundll32 Abuse",
        "severity": "HIGH",
        "description": "Suspicious rundll32 execution detected."
    },

    1161: {
        "name": "Regsvr32 Abuse",
        "severity": "HIGH",
        "description": "Potential malicious regsvr32 execution detected."
    },

    1162: {
        "name": "WMIC Abuse",
        "severity": "HIGH",
        "description": "Suspicious WMIC command execution detected."
    },

    1163: {
        "name": "Psexec Activity",
        "severity": "HIGH",
        "description": "Remote execution via PsExec detected."
    },

    1164: {
        "name": "Remote Service Execution",
        "severity": "HIGH",
        "description": "Potential remote service execution activity detected."
    },

    1165: {
        "name": "Suspicious Admin Share Access",
        "severity": "HIGH",
        "description": "Administrative network share accessed unexpectedly."
    },

    1166: {
        "name": "Remote Registry Access",
        "severity": "HIGH",
        "description": "Remote registry access detected."
    },

    1167: {
        "name": "Credential Delegation Abuse",
        "severity": "HIGH",
        "description": "Potential abuse of delegated credentials detected."
    },

    1168: {
        "name": "Remote Code Injection",
        "severity": "CRITICAL",
        "description": "Remote code injection behavior detected."
    },

    1169: {
        "name": "Process Hollowing Detected",
        "severity": "CRITICAL",
        "description": "Process hollowing attack behavior detected."
    },

    1170: {
        "name": "Suspicious Process Replacement",
        "severity": "HIGH",
        "description": "Potential process replacement activity detected."
    },

    1171: {
        "name": "Parent PID Spoofing",
        "severity": "HIGH",
        "description": "Potential parent process ID spoofing detected."
    },

    1172: {
        "name": "Thread Hijacking Detected",
        "severity": "HIGH",
        "description": "Suspicious thread hijacking activity detected."
    },

    1173: {
        "name": "APC Injection Detected",
        "severity": "HIGH",
        "description": "Asynchronous Procedure Call injection detected."
    },

    1174: {
        "name": "Reflective DLL Injection",
        "severity": "CRITICAL",
        "description": "Reflective DLL injection behavior detected."
    },

    1175: {
        "name": "Shellcode Execution",
        "severity": "CRITICAL",
        "description": "Potential shellcode execution detected."
    },

    1176: {
        "name": "Executable Memory Allocation",
        "severity": "HIGH",
        "description": "Suspicious executable memory allocation detected."
    },

    1177: {
        "name": "Memory Protection Modification",
        "severity": "HIGH",
        "description": "Process memory protection modified unexpectedly."
    },

    1178: {
        "name": "Direct System Call Usage",
        "severity": "HIGH",
        "description": "Direct system call execution detected."
    },

    1179: {
        "name": "Unhooking Security APIs",
        "severity": "HIGH",
        "description": "Security monitoring API unhooking detected."
    },

    1180: {
        "name": "EDR Evasion Attempt",
        "severity": "CRITICAL",
        "description": "Potential endpoint detection evasion detected."
    },

    1181: {
        "name": "Security Tool Termination",
        "severity": "CRITICAL",
        "description": "Security monitoring process terminated unexpectedly."
    },

    1182: {
        "name": "AV Process Tampering",
        "severity": "CRITICAL",
        "description": "Antivirus process tampering activity detected."
    },

    1183: {
        "name": "SIEM Agent Disabled",
        "severity": "HIGH",
        "description": "Security monitoring agent disabled."
    },

    1184: {
        "name": "Sysmon Service Disabled",
        "severity": "HIGH",
        "description": "Sysmon monitoring service disabled."
    },

    1185: {
        "name": "Log Forwarding Interrupted",
        "severity": "MEDIUM",
        "description": "Security log forwarding interruption detected."
    },

    1186: {
        "name": "Audit Policy Enumeration",
        "severity": "MEDIUM",
        "description": "Audit policy enumeration activity detected."
    },

    1187: {
        "name": "Security Product Enumeration",
        "severity": "MEDIUM",
        "description": "Enumeration of installed security products detected."
    },

    1188: {
        "name": "Environment Discovery Activity",
        "severity": "MEDIUM",
        "description": "System environment discovery behavior detected."
    },

    1189: {
        "name": "System Information Discovery",
        "severity": "LOW",
        "description": "System information enumeration detected."
    },

    1190: {
        "name": "User Enumeration Activity",
        "severity": "MEDIUM",
        "description": "Potential user account enumeration detected."
    },

    1191: {
        "name": "Group Enumeration Activity",
        "severity": "MEDIUM",
        "description": "Security group enumeration detected."
    },

    1192: {
        "name": "Installed Software Enumeration",
        "severity": "LOW",
        "description": "Installed software inventory enumeration detected."
    },

    1193: {
        "name": "Network Configuration Discovery",
        "severity": "LOW",
        "description": "Network configuration discovery activity detected."
    },

    1194: {
        "name": "Domain Trust Discovery",
        "severity": "MEDIUM",
        "description": "Domain trust relationship enumeration detected."
    },

    1195: {
        "name": "ARP Table Enumeration",
        "severity": "LOW",
        "description": "ARP cache or table enumeration detected."
    },

    1196: {
        "name": "Routing Table Enumeration",
        "severity": "LOW",
        "description": "Routing table discovery activity detected."
    },

    1197: {
        "name": "Security Identifier Enumeration",
        "severity": "MEDIUM",
        "description": "SID enumeration activity detected."
    },

    1198: {
        "name": "Domain Controller Discovery",
        "severity": "MEDIUM",
        "description": "Domain controller discovery behavior detected."
    },

    1199: {
        "name": "Password Policy Discovery",
        "severity": "MEDIUM",
        "description": "Password policy enumeration detected."
    },

    1200: {
        "name": "Virtual Machine Detection",
        "severity": "MEDIUM",
        "description": "Virtualization or sandbox detection behavior observed."
    },

    1201: {
        "name": "Debugger Detection",
        "severity": "HIGH",
        "description": "Anti-debugging behavior detected."
    },

    1202: {
        "name": "Sandbox Evasion Attempt",
        "severity": "HIGH",
        "description": "Potential sandbox evasion technique detected."
    },

    1203: {
        "name": "Sleep Delay Evasion",
        "severity": "MEDIUM",
        "description": "Extended sleep delay used for evasion detected."
    },

    1204: {
        "name": "Time-Based Execution Evasion",
        "severity": "MEDIUM",
        "description": "Delayed execution technique detected."
    },

    1205: {
        "name": "Persistence Through WMI Event Subscription",
        "severity": "HIGH",
        "description": "WMI event subscription persistence detected."
    },

    1206: {
        "name": "Malicious Browser Extension Installed",
        "severity": "HIGH",
        "description": "Potentially malicious browser extension installation detected."
    },

    1207: {
        "name": "Browser Credential Theft",
        "severity": "CRITICAL",
        "description": "Potential browser credential theft detected."
    },

    1208: {
        "name": "Cookie Theft Activity",
        "severity": "HIGH",
        "description": "Suspicious browser cookie access detected."
    },

    1209: {
        "name": "Session Token Theft",
        "severity": "CRITICAL",
        "description": "Potential session token theft detected."
    },

        1210: {
        "name": "Clipboard Data Theft",
        "severity": "HIGH",
        "description": "Sensitive clipboard content access detected."
    },

    1211: {
        "name": "Browser History Enumeration",
        "severity": "MEDIUM",
        "description": "Browser history collection activity detected."
    },

    1212: {
        "name": "Saved Credential Access",
        "severity": "CRITICAL",
        "description": "Access to stored application credentials detected."
    },

    1213: {
        "name": "Credential Manager Dump",
        "severity": "CRITICAL",
        "description": "Windows Credential Manager dumping activity detected."
    },

    1214: {
        "name": "SAM Registry Hive Access",
        "severity": "CRITICAL",
        "description": "SAM registry hive accessed unexpectedly."
    },

    1215: {
        "name": "NTDS Database Access",
        "severity": "CRITICAL",
        "description": "Potential unauthorized NTDS.dit access detected."
    },

    1216: {
        "name": "LSASS Memory Dump",
        "severity": "CRITICAL",
        "description": "LSASS process memory dumping detected."
    },

    1217: {
        "name": "MiniDump Utility Execution",
        "severity": "HIGH",
        "description": "Potential credential dumping utility execution detected."
    },

    1218: {
        "name": "Unauthorized Volume Shadow Copy Access",
        "severity": "HIGH",
        "description": "Unauthorized access to volume shadow copies detected."
    },

    1219: {
        "name": "Disk Imaging Activity",
        "severity": "HIGH",
        "description": "Potential full disk imaging operation detected."
    },

    1220: {
        "name": "Forensic Tool Execution",
        "severity": "MEDIUM",
        "description": "Known forensic or credential extraction tool executed."
    },

    1221: {
        "name": "Packet Capture Tool Execution",
        "severity": "HIGH",
        "description": "Network packet capture utility execution detected."
    },

    1222: {
        "name": "Raw Socket Access",
        "severity": "HIGH",
        "description": "Raw socket creation or access detected."
    },

    1223: {
        "name": "Promiscuous Mode Enabled",
        "severity": "HIGH",
        "description": "Network adapter switched to promiscuous mode."
    },

    1224: {
        "name": "Unauthorized Proxy Configuration",
        "severity": "HIGH",
        "description": "System proxy settings modified unexpectedly."
    },

    1225: {
        "name": "Hosts File Modification",
        "severity": "HIGH",
        "description": "Hosts file modified unexpectedly."
    },

    1226: {
        "name": "DNS Resolver Configuration Changed",
        "severity": "MEDIUM",
        "description": "DNS resolver settings modified."
    },

    1227: {
        "name": "Unauthorized VPN Profile Added",
        "severity": "HIGH",
        "description": "VPN configuration profile added unexpectedly."
    },

    1228: {
        "name": "Wireless Network Profile Added",
        "severity": "LOW",
        "description": "New wireless network profile created."
    },

    1229: {
        "name": "Suspicious Wi-Fi Connection",
        "severity": "MEDIUM",
        "description": "Connection to suspicious wireless network detected."
    },

    1230: {
        "name": "Bluetooth Device Paired",
        "severity": "LOW",
        "description": "Bluetooth device pairing activity detected."
    },

    1231: {
        "name": "Unauthorized Bluetooth Access",
        "severity": "MEDIUM",
        "description": "Unexpected Bluetooth communication detected."
    },

    1232: {
        "name": "Remote Desktop Configuration Changed",
        "severity": "HIGH",
        "description": "Remote Desktop settings modified."
    },

    1233: {
        "name": "RDP Network Level Authentication Disabled",
        "severity": "HIGH",
        "description": "RDP Network Level Authentication disabled."
    },

    1234: {
        "name": "Remote Assistance Enabled",
        "severity": "MEDIUM",
        "description": "Windows Remote Assistance enabled."
    },

    1235: {
        "name": "Terminal Services Abuse",
        "severity": "HIGH",
        "description": "Potential abuse of terminal services detected."
    },

    1236: {
        "name": "Excessive Failed RDP Logins",
        "severity": "CRITICAL",
        "description": "Multiple failed RDP authentication attempts detected."
    },

    1237: {
        "name": "RDP Session Hijacking",
        "severity": "CRITICAL",
        "description": "Potential RDP session hijacking detected."
    },

    1238: {
        "name": "Remote Desktop Shadowing",
        "severity": "HIGH",
        "description": "Remote Desktop session shadowing detected."
    },

    1239: {
        "name": "Unauthorized Remote Access Tool",
        "severity": "CRITICAL",
        "description": "Unauthorized remote administration tool detected."
    },

    1240: {
        "name": "Persistence Via Registry Run Key",
        "severity": "HIGH",
        "description": "Registry Run key persistence mechanism detected."
    },

    1241: {
        "name": "Persistence Via Startup Script",
        "severity": "HIGH",
        "description": "Startup script persistence activity detected."
    },

    1242: {
        "name": "Persistence Via Service",
        "severity": "HIGH",
        "description": "Service-based persistence mechanism detected."
    },

    1243: {
        "name": "Persistence Via DLL Hijacking",
        "severity": "HIGH",
        "description": "DLL hijacking persistence detected."
    },

    1244: {
        "name": "Persistence Via Browser Extension",
        "severity": "MEDIUM",
        "description": "Browser extension persistence mechanism detected."
    },

    1245: {
        "name": "Persistence Via WMI",
        "severity": "HIGH",
        "description": "WMI-based persistence detected."
    },

    1246: {
        "name": "Persistence Via COM Object",
        "severity": "HIGH",
        "description": "COM object persistence activity detected."
    },

    1247: {
        "name": "Persistence Via Scheduled Task",
        "severity": "HIGH",
        "description": "Scheduled task persistence mechanism detected."
    },

    1248: {
        "name": "Persistence Via Shortcut Modification",
        "severity": "MEDIUM",
        "description": "Shortcut file modified for persistence."
    },

    1249: {
        "name": "Persistence Via Winlogon Helper",
        "severity": "HIGH",
        "description": "Winlogon helper persistence mechanism detected."
    },

    1250: {
        "name": "Persistence Via AppInit DLL",
        "severity": "HIGH",
        "description": "AppInit DLL persistence detected."
    },

    1251: {
        "name": "Persistence Via IFEO",
        "severity": "HIGH",
        "description": "Image File Execution Options persistence detected."
    },

    1252: {
        "name": "Persistence Via Accessibility Feature",
        "severity": "HIGH",
        "description": "Accessibility feature abuse for persistence detected."
    },

    1253: {
        "name": "Sticky Keys Backdoor",
        "severity": "CRITICAL",
        "description": "Sticky Keys backdoor modification detected."
    },

    1254: {
        "name": "Unauthorized Accessibility Binary Replacement",
        "severity": "CRITICAL",
        "description": "Accessibility binary replacement detected."
    },

    1255: {
        "name": "Persistence Via Print Processor",
        "severity": "HIGH",
        "description": "Print processor persistence mechanism detected."
    },

    1256: {
        "name": "Persistence Via Office Add-in",
        "severity": "MEDIUM",
        "description": "Office add-in persistence detected."
    },

    1257: {
        "name": "Malicious Office Template",
        "severity": "HIGH",
        "description": "Potential malicious Office template detected."
    },

    1258: {
        "name": "Office Child Process Spawn",
        "severity": "HIGH",
        "description": "Office application spawned suspicious child process."
    },

    1259: {
        "name": "Macro Spawned PowerShell",
        "severity": "CRITICAL",
        "description": "Office macro spawned PowerShell process."
    },

    1260: {
        "name": "Office External Template Injection",
        "severity": "HIGH",
        "description": "Office document loaded external template."
    },

    1261: {
        "name": "Suspicious OneNote Attachment Execution",
        "severity": "HIGH",
        "description": "Potential malicious OneNote attachment execution detected."
    },

    1262: {
        "name": "HTA File Execution",
        "severity": "HIGH",
        "description": "HTA application execution detected."
    },

    1263: {
        "name": "JavaScript Dropper Execution",
        "severity": "HIGH",
        "description": "Potential JavaScript malware dropper execution detected."
    },

    1264: {
        "name": "VBScript Execution",
        "severity": "MEDIUM",
        "description": "VBScript execution activity detected."
    },

    1265: {
        "name": "Suspicious Batch Script Execution",
        "severity": "MEDIUM",
        "description": "Potential malicious batch script execution detected."
    },

        1266: {
        "name": "Suspicious ISO Mount Activity",
        "severity": "MEDIUM",
        "description": "Potential malicious ISO image mounting detected."
    },

    1267: {
        "name": "Malicious LNK File Execution",
        "severity": "HIGH",
        "description": "Suspicious shortcut file execution detected."
    },

    1268: {
        "name": "Executable From Temp Directory",
        "severity": "HIGH",
        "description": "Executable launched from temporary directory."
    },

    1269: {
        "name": "Execution From Downloads Folder",
        "severity": "MEDIUM",
        "description": "Executable launched from downloads directory."
    },

    1270: {
        "name": "Unsigned Binary Execution",
        "severity": "HIGH",
        "description": "Unsigned executable binary launched."
    },

    1271: {
        "name": "Suspicious Parent Child Process Chain",
        "severity": "HIGH",
        "description": "Abnormal parent-child process relationship detected."
    },

    1272: {
        "name": "Command-Line Obfuscation",
        "severity": "HIGH",
        "description": "Obfuscated command-line arguments detected."
    },

    1273: {
        "name": "Base64 Encoded Payload",
        "severity": "HIGH",
        "description": "Base64 encoded payload execution detected."
    },

    1274: {
        "name": "PowerShell Download Cradle",
        "severity": "CRITICAL",
        "description": "PowerShell download cradle behavior detected."
    },

    1275: {
        "name": "AMSI Bypass Attempt",
        "severity": "CRITICAL",
        "description": "Potential AMSI bypass technique detected."
    },

    1276: {
        "name": "Suspicious PowerShell Reflection",
        "severity": "HIGH",
        "description": "PowerShell reflection or in-memory execution detected."
    },

    1277: {
        "name": "Encoded Command Prompt Usage",
        "severity": "HIGH",
        "description": "Encoded command execution via command prompt detected."
    },

    1278: {
        "name": "Wscript Suspicious Execution",
        "severity": "HIGH",
        "description": "Potential malicious wscript execution detected."
    },

    1279: {
        "name": "Cscript Suspicious Execution",
        "severity": "HIGH",
        "description": "Potential malicious cscript execution detected."
    },

    1280: {
        "name": "MSBuild Abuse",
        "severity": "HIGH",
        "description": "Potential malicious MSBuild execution detected."
    },

    1281: {
        "name": "InstallUtil Abuse",
        "severity": "HIGH",
        "description": "Potential malicious InstallUtil execution detected."
    },

    1282: {
        "name": "RegAsm Abuse",
        "severity": "HIGH",
        "description": "Potential malicious RegAsm execution detected."
    },

    1283: {
        "name": "RegSvcs Abuse",
        "severity": "HIGH",
        "description": "Potential malicious RegSvcs execution detected."
    },

    1284: {
        "name": "Msiexec Remote Install",
        "severity": "HIGH",
        "description": "Remote MSI package installation detected."
    },

    1285: {
        "name": "Suspicious DLL Registration",
        "severity": "HIGH",
        "description": "Unexpected DLL registration activity detected."
    },

    1286: {
        "name": "Untrusted Binary Network Access",
        "severity": "HIGH",
        "description": "Untrusted process initiated outbound network connection."
    },

    1287: {
        "name": "Hidden Process Execution",
        "severity": "HIGH",
        "description": "Process executed with hidden window or stealth options."
    },

    1288: {
        "name": "Suspicious Mutex Creation",
        "severity": "MEDIUM",
        "description": "Potential malware mutex creation detected."
    },

    1289: {
        "name": "Process Masquerading",
        "severity": "CRITICAL",
        "description": "Process masquerading as legitimate application detected."
    },

    1290: {
        "name": "Binary Renamed To Trusted Name",
        "severity": "HIGH",
        "description": "Executable renamed to mimic trusted application."
    },

    1291: {
        "name": "Living-Off-The-Land Script",
        "severity": "HIGH",
        "description": "Living-off-the-land scripting activity detected."
    },

    1292: {
        "name": "Remote Payload Download",
        "severity": "CRITICAL",
        "description": "Payload downloaded from remote server."
    },

    1293: {
        "name": "Suspicious HTTP Beacon",
        "severity": "HIGH",
        "description": "Periodic HTTP beacon communication detected."
    },

    1294: {
        "name": "HTTPS Beaconing Activity",
        "severity": "HIGH",
        "description": "Encrypted outbound beaconing detected."
    },

    1295: {
        "name": "Suspicious User-Agent String",
        "severity": "MEDIUM",
        "description": "Suspicious or spoofed HTTP User-Agent observed."
    },

    1296: {
        "name": "Command And Control Traffic",
        "severity": "CRITICAL",
        "description": "Potential command-and-control communication detected."
    },

    1297: {
        "name": "Outbound Connection To Rare Domain",
        "severity": "MEDIUM",
        "description": "Connection to rare or previously unseen domain detected."
    },

    1298: {
        "name": "Outbound Connection To Blacklisted IP",
        "severity": "CRITICAL",
        "description": "Connection established to blacklisted IP address."
    },

    1299: {
        "name": "TOR Exit Node Communication",
        "severity": "HIGH",
        "description": "Communication with TOR exit node detected."
    },

    1300: {
        "name": "Fast Flux DNS Activity",
        "severity": "HIGH",
        "description": "Fast flux DNS behavior detected."
    },

    1301: {
        "name": "Domain Generation Algorithm Activity",
        "severity": "CRITICAL",
        "description": "Potential DGA-based domain communication detected."
    },

    1302: {
        "name": "Suspicious DNS TXT Query",
        "severity": "HIGH",
        "description": "Potential DNS TXT-based command channel detected."
    },

    1303: {
        "name": "Long DNS Query Detected",
        "severity": "MEDIUM",
        "description": "Abnormally long DNS query observed."
    },

    1304: {
        "name": "Suspicious DNS Subdomain Pattern",
        "severity": "HIGH",
        "description": "Potential DNS tunneling subdomain pattern detected."
    },

    1305: {
        "name": "Excessive NXDOMAIN Responses",
        "severity": "MEDIUM",
        "description": "Large number of failed DNS lookups detected."
    },

    1306: {
        "name": "ICMP Tunnel Activity",
        "severity": "CRITICAL",
        "description": "Potential ICMP tunneling communication detected."
    },

    1307: {
        "name": "Unusual Port Communication",
        "severity": "MEDIUM",
        "description": "Traffic observed over unusual network port."
    },

    1308: {
        "name": "Outbound SMB Traffic",
        "severity": "HIGH",
        "description": "Unexpected outbound SMB communication detected."
    },

    1309: {
        "name": "Suspicious LDAP Traffic",
        "severity": "MEDIUM",
        "description": "Abnormal LDAP communication detected."
    },

    1310: {
        "name": "Suspicious Kerberos Traffic",
        "severity": "HIGH",
        "description": "Abnormal Kerberos traffic pattern detected."
    },

    1311: {
        "name": "Unauthorized SNMP Query",
        "severity": "MEDIUM",
        "description": "Unexpected SNMP query activity detected."
    },

    1312: {
        "name": "Network Discovery Scan",
        "severity": "HIGH",
        "description": "Host discovery scanning activity detected."
    },

    1313: {
        "name": "Lateral Movement Over SMB",
        "severity": "CRITICAL",
        "description": "Potential lateral movement via SMB detected."
    },

    1314: {
        "name": "Remote Service Creation Over Network",
        "severity": "HIGH",
        "description": "Remote service creation activity detected."
    },

    1315: {
        "name": "Unauthorized WinRM Usage",
        "severity": "HIGH",
        "description": "Unexpected WinRM remote management activity detected."
    },

    1316: {
        "name": "Suspicious RPC Activity",
        "severity": "MEDIUM",
        "description": "Potential malicious RPC communication detected."
    },

    1317: {
        "name": "Firewall Rule Enumeration",
        "severity": "LOW",
        "description": "Firewall rule enumeration activity detected."
    },

    1318: {
        "name": "Firewall Rule Tampering",
        "severity": "HIGH",
        "description": "Unauthorized firewall rule modification detected."
    },

    1319: {
        "name": "Firewall Disabled",
        "severity": "CRITICAL",
        "description": "Host firewall protection disabled."
    },

    1320: {
        "name": "Inbound Allow Rule Added",
        "severity": "HIGH",
        "description": "New inbound allow firewall rule added."
    },
    
        1321: {
        "name": "Outbound Allow Rule Added",
        "severity": "HIGH",
        "description": "New outbound allow firewall rule added."
    },

    1322: {
        "name": "Firewall Logging Disabled",
        "severity": "HIGH",
        "description": "Firewall logging functionality disabled."
    },

    1323: {
        "name": "Unauthorized Port Forwarding",
        "severity": "HIGH",
        "description": "Potential unauthorized port forwarding detected."
    },

    1324: {
        "name": "Proxy Bypass Attempt",
        "severity": "HIGH",
        "description": "Attempt to bypass enterprise proxy controls detected."
    },

    1325: {
        "name": "Suspicious SOCKS Proxy Usage",
        "severity": "HIGH",
        "description": "Potential SOCKS proxy tunneling activity detected."
    },

    1326: {
        "name": "VPN Split Tunneling Enabled",
        "severity": "MEDIUM",
        "description": "VPN split tunneling configuration detected."
    },

    1327: {
        "name": "Unauthorized Network Bridge",
        "severity": "HIGH",
        "description": "Unexpected network bridge configuration detected."
    },

    1328: {
        "name": "ARP Cache Poisoning",
        "severity": "CRITICAL",
        "description": "ARP cache poisoning activity detected."
    },

    1329: {
        "name": "MAC Address Spoofing",
        "severity": "HIGH",
        "description": "Potential MAC address spoofing detected."
    },

    1330: {
        "name": "DHCP Spoofing Activity",
        "severity": "HIGH",
        "description": "Unauthorized DHCP server behavior detected."
    },

    1331: {
        "name": "Rogue Access Point Detected",
        "severity": "HIGH",
        "description": "Potential rogue wireless access point detected."
    },

    1332: {
        "name": "Unexpected Wireless Authentication",
        "severity": "MEDIUM",
        "description": "Unexpected wireless authentication attempt observed."
    },

    1333: {
        "name": "Network Interface Disabled",
        "severity": "MEDIUM",
        "description": "Network interface disabled unexpectedly."
    },

    1334: {
        "name": "Network Interface Configuration Changed",
        "severity": "MEDIUM",
        "description": "Network interface settings modified."
    },

    1335: {
        "name": "Static IP Address Configured",
        "severity": "LOW",
        "description": "Static IP configuration detected."
    },

    1336: {
        "name": "Unauthorized DNS Server Change",
        "severity": "HIGH",
        "description": "DNS server configuration modified unexpectedly."
    },

    1337: {
        "name": "Gateway Configuration Modified",
        "severity": "MEDIUM",
        "description": "Default gateway configuration changed."
    },

    1338: {
        "name": "Network Route Injection",
        "severity": "HIGH",
        "description": "Suspicious network route injection detected."
    },

    1339: {
        "name": "Suspicious VPN Client Execution",
        "severity": "MEDIUM",
        "description": "Unexpected VPN client execution detected."
    },

    1340: {
        "name": "Unauthorized Remote Tunnel",
        "severity": "CRITICAL",
        "description": "Potential unauthorized remote tunneling detected."
    },

    1341: {
        "name": "SSH Tunnel Activity",
        "severity": "HIGH",
        "description": "SSH tunneling activity detected."
    },

    1342: {
        "name": "Reverse Proxy Tunnel",
        "severity": "CRITICAL",
        "description": "Reverse proxy tunnel communication detected."
    },

    1343: {
        "name": "Network Packet Fragmentation Abuse",
        "severity": "HIGH",
        "description": "Suspicious fragmented packet activity detected."
    },

    1344: {
        "name": "TCP SYN Flood Attack",
        "severity": "CRITICAL",
        "description": "TCP SYN flood denial-of-service activity detected."
    },

    1345: {
        "name": "UDP Flood Attack",
        "severity": "CRITICAL",
        "description": "UDP flood attack traffic detected."
    },

    1346: {
        "name": "ICMP Flood Attack",
        "severity": "CRITICAL",
        "description": "ICMP flood attack activity detected."
    },

    1347: {
        "name": "HTTP Flood Activity",
        "severity": "HIGH",
        "description": "Potential HTTP flood attack detected."
    },

    1348: {
        "name": "Slowloris Attack Pattern",
        "severity": "HIGH",
        "description": "Slowloris denial-of-service behavior detected."
    },

    1349: {
        "name": "Excessive Failed Connections",
        "severity": "MEDIUM",
        "description": "Large number of failed network connections detected."
    },

    1350: {
        "name": "Unusual East-West Traffic",
        "severity": "MEDIUM",
        "description": "Abnormal lateral network traffic detected."
    },

    1351: {
        "name": "Unauthorized Internal Service Access",
        "severity": "HIGH",
        "description": "Unexpected access to internal service detected."
    },

    1352: {
        "name": "Excessive SMB Authentication Requests",
        "severity": "HIGH",
        "description": "Large volume SMB authentication activity detected."
    },

    1353: {
        "name": "Anonymous SMB Login",
        "severity": "HIGH",
        "description": "Anonymous SMB authentication attempt detected."
    },

    1354: {
        "name": "NTLM Authentication Downgrade",
        "severity": "HIGH",
        "description": "NTLM authentication downgrade attempt detected."
    },

    1355: {
        "name": "LLMNR Poisoning Activity",
        "severity": "CRITICAL",
        "description": "Potential LLMNR/NBT-NS poisoning attack detected."
    },

    1356: {
        "name": "NetBIOS Enumeration",
        "severity": "MEDIUM",
        "description": "NetBIOS enumeration activity detected."
    },

    1357: {
        "name": "Unexpected LDAP Bind Request",
        "severity": "MEDIUM",
        "description": "Suspicious LDAP bind activity detected."
    },

    1358: {
        "name": "LDAP Anonymous Query",
        "severity": "HIGH",
        "description": "Anonymous LDAP query attempt detected."
    },

    1359: {
        "name": "Suspicious DNS Zone Enumeration",
        "severity": "HIGH",
        "description": "Potential DNS zone enumeration activity detected."
    },

    1360: {
        "name": "DNS Wildcard Querying",
        "severity": "MEDIUM",
        "description": "Abnormal wildcard DNS query activity detected."
    },

    1361: {
        "name": "Abnormal GeoIP Connection",
        "severity": "HIGH",
        "description": "Connection to unusual geographic region detected."
    },

    1362: {
        "name": "Impossible Travel Activity",
        "severity": "HIGH",
        "description": "Authentication from geographically impossible locations detected."
    },

    1363: {
        "name": "Rare Country Authentication",
        "severity": "MEDIUM",
        "description": "Login from rare or unusual country detected."
    },

    1364: {
        "name": "Off-Hours Administrative Login",
        "severity": "MEDIUM",
        "description": "Administrative login outside business hours detected."
    },

    1365: {
        "name": "Concurrent User Sessions",
        "severity": "MEDIUM",
        "description": "Multiple simultaneous user sessions detected."
    },

    1366: {
        "name": "Shared Account Usage",
        "severity": "HIGH",
        "description": "Potential shared account activity detected."
    },

    1367: {
        "name": "Dormant Account Login",
        "severity": "HIGH",
        "description": "Authentication using dormant account detected."
    },

    1368: {
        "name": "Disabled Account Authentication Attempt",
        "severity": "HIGH",
        "description": "Disabled account attempted authentication."
    },

    1369: {
        "name": "Expired Account Login Attempt",
        "severity": "MEDIUM",
        "description": "Expired account authentication attempt detected."
    },

    1370: {
        "name": "Service Account Interactive Login",
        "severity": "HIGH",
        "description": "Service account used for interactive login."
    },

    1371: {
        "name": "Privileged Account Enumeration",
        "severity": "HIGH",
        "description": "Enumeration of privileged accounts detected."
    },

    1372: {
        "name": "Unexpected Privilege Assignment",
        "severity": "HIGH",
        "description": "Unexpected administrative privilege assignment detected."
    },

    1373: {
        "name": "Unauthorized Group Membership Change",
        "severity": "HIGH",
        "description": "Security group membership modified unexpectedly."
    },

    1374: {
        "name": "Delegation Rights Assigned",
        "severity": "HIGH",
        "description": "Delegation rights assigned to account."
    },

    1375: {
        "name": "Constrained Delegation Abuse",
        "severity": "CRITICAL",
        "description": "Potential constrained delegation abuse detected."
    },

    1376: {
        "name": "SID History Injection",
        "severity": "CRITICAL",
        "description": "Potential SID History injection detected."
    },

    1377: {
        "name": "Skeleton Key Malware Activity",
        "severity": "CRITICAL",
        "description": "Potential Skeleton Key malware behavior detected."
    },

    1378: {
        "name": "DCShadow Attack Activity",
        "severity": "CRITICAL",
        "description": "Potential DCShadow attack detected."
    },

    1379: {
        "name": "Unauthorized Domain Admin Access",
        "severity": "CRITICAL",
        "description": "Unexpected Domain Admin activity detected."
    },

    1380: {
        "name": "Replication Service Abuse",
        "severity": "CRITICAL",
        "description": "Potential abuse of directory replication services detected."
    },

        1381: {
        "name": "Unauthorized Trust Relationship",
        "severity": "CRITICAL",
        "description": "Unexpected domain trust relationship modification detected."
    },

    1382: {
        "name": "Forest Enumeration Activity",
        "severity": "MEDIUM",
        "description": "Active Directory forest enumeration detected."
    },

    1383: {
        "name": "Domain Policy Enumeration",
        "severity": "LOW",
        "description": "Domain policy enumeration activity detected."
    },

    1384: {
        "name": "AdminSDHolder Modification",
        "severity": "CRITICAL",
        "description": "AdminSDHolder object modified unexpectedly."
    },

    1385: {
        "name": "KRBTGT Account Modification",
        "severity": "CRITICAL",
        "description": "KRBTGT account modification detected."
    },

    1386: {
        "name": "Suspicious SPN Registration",
        "severity": "HIGH",
        "description": "Unexpected Service Principal Name registration detected."
    },

    1387: {
        "name": "ADCS Enumeration Activity",
        "severity": "MEDIUM",
        "description": "Active Directory Certificate Services enumeration detected."
    },

    1388: {
        "name": "Certificate Template Abuse",
        "severity": "CRITICAL",
        "description": "Potential certificate template abuse detected."
    },

    1389: {
        "name": "ESC1 Certificate Abuse",
        "severity": "CRITICAL",
        "description": "Potential ESC1 certificate abuse activity detected."
    },

    1390: {
        "name": "ESC8 NTLM Relay To ADCS",
        "severity": "CRITICAL",
        "description": "Potential NTLM relay attack against ADCS detected."
    },

    1391: {
        "name": "Unauthorized Certificate Export",
        "severity": "HIGH",
        "description": "Certificate private key export detected."
    },

    1392: {
        "name": "Certificate Theft Activity",
        "severity": "CRITICAL",
        "description": "Potential certificate theft activity detected."
    },

    1393: {
        "name": "Smart Card Certificate Abuse",
        "severity": "HIGH",
        "description": "Suspicious smart card certificate usage detected."
    },

    1394: {
        "name": "Code Signing Certificate Abuse",
        "severity": "CRITICAL",
        "description": "Potential malicious code-signing certificate usage detected."
    },

    1395: {
        "name": "Unauthorized CA Enrollment Agent",
        "severity": "CRITICAL",
        "description": "Unexpected certificate enrollment agent activity detected."
    },

    1396: {
        "name": "Suspicious PKINIT Authentication",
        "severity": "HIGH",
        "description": "Suspicious PKINIT Kerberos authentication detected."
    },

    1397: {
        "name": "Kerberos Delegation Abuse",
        "severity": "CRITICAL",
        "description": "Potential Kerberos delegation abuse detected."
    },

    1398: {
        "name": "Unconstrained Delegation Enabled",
        "severity": "CRITICAL",
        "description": "Unconstrained delegation configuration detected."
    },

    1399: {
        "name": "Resource-Based Constrained Delegation",
        "severity": "CRITICAL",
        "description": "Resource-based constrained delegation abuse detected."
    },

    1400: {
        "name": "Domain Controller Shadow Copy Access",
        "severity": "CRITICAL",
        "description": "Shadow copy access on domain controller detected."
    },

    1401: {
        "name": "Sysmon Process Creation",
        "severity": "LOW",
        "description": "Sysmon process creation event logged."
    },

    1402: {
        "name": "Sysmon File Creation Time Changed",
        "severity": "MEDIUM",
        "description": "File creation timestamp modification detected."
    },

    1403: {
        "name": "Sysmon Network Connection",
        "severity": "LOW",
        "description": "Network connection event recorded by Sysmon."
    },

    1404: {
        "name": "Sysmon Driver Loaded",
        "severity": "HIGH",
        "description": "Kernel driver loaded into system memory."
    },

    1405: {
        "name": "Sysmon Process Terminated",
        "severity": "LOW",
        "description": "Process termination recorded by Sysmon."
    },

    1406: {
        "name": "Sysmon Driver Tampering",
        "severity": "CRITICAL",
        "description": "Potential tampering with Sysmon driver detected."
    },

    1407: {
        "name": "Sysmon Image Load",
        "severity": "MEDIUM",
        "description": "DLL or executable image loaded into process memory."
    },

    1408: {
        "name": "Sysmon Remote Thread Creation",
        "severity": "HIGH",
        "description": "Remote thread creation detected by Sysmon."
    },

    1409: {
        "name": "Sysmon Raw Disk Access",
        "severity": "HIGH",
        "description": "Raw disk access activity detected."
    },

    1410: {
        "name": "Sysmon Process Access",
        "severity": "HIGH",
        "description": "Sensitive process access detected by Sysmon."
    },

    1411: {
        "name": "Sysmon File Creation",
        "severity": "LOW",
        "description": "File creation activity recorded by Sysmon."
    },

    1412: {
        "name": "Sysmon Registry Modification",
        "severity": "MEDIUM",
        "description": "Registry object modification detected."
    },

    1413: {
        "name": "Sysmon Registry Value Set",
        "severity": "MEDIUM",
        "description": "Registry value modification recorded."
    },

    1414: {
        "name": "Sysmon Registry Key Rename",
        "severity": "MEDIUM",
        "description": "Registry key rename operation detected."
    },

    1415: {
        "name": "Sysmon Alternate Data Stream Created",
        "severity": "HIGH",
        "description": "Alternate Data Stream creation detected."
    },

    1416: {
        "name": "Sysmon Named Pipe Created",
        "severity": "MEDIUM",
        "description": "Named pipe creation activity detected."
    },

    1417: {
        "name": "Sysmon Named Pipe Connection",
        "severity": "MEDIUM",
        "description": "Named pipe connection recorded."
    },

    1418: {
        "name": "Sysmon WMI Event Filter Activity",
        "severity": "HIGH",
        "description": "WMI event filter modification detected."
    },

    1419: {
        "name": "Sysmon WMI Consumer Activity",
        "severity": "HIGH",
        "description": "WMI consumer modification detected."
    },

    1420: {
        "name": "Sysmon WMI Binding Activity",
        "severity": "HIGH",
        "description": "WMI filter-to-consumer binding detected."
    },

    1421: {
        "name": "Sysmon DNS Query Logged",
        "severity": "LOW",
        "description": "DNS query activity recorded by Sysmon."
    },

    1422: {
        "name": "Sysmon File Delete Detected",
        "severity": "MEDIUM",
        "description": "File deletion event detected."
    },

    1423: {
        "name": "Sysmon Clipboard Change",
        "severity": "MEDIUM",
        "description": "Clipboard content modification detected."
    },

    1424: {
        "name": "Sysmon Process Tampering",
        "severity": "CRITICAL",
        "description": "Process tampering behavior detected."
    },

    1425: {
        "name": "Suspicious Sysmon Configuration Change",
        "severity": "HIGH",
        "description": "Sysmon configuration modified unexpectedly."
    },

    1426: {
        "name": "Sysmon Event Dropping",
        "severity": "HIGH",
        "description": "Potential Sysmon event suppression detected."
    },

    1427: {
        "name": "Sysmon Rule Bypass Attempt",
        "severity": "CRITICAL",
        "description": "Potential attempt to bypass Sysmon monitoring rules detected."
    },

    1428: {
        "name": "Process Injection Via Sysmon",
        "severity": "CRITICAL",
        "description": "Sysmon identified process injection behavior."
    },

    1429: {
        "name": "Unsigned Driver Via Sysmon",
        "severity": "HIGH",
        "description": "Unsigned driver load recorded by Sysmon."
    },

    1430: {
        "name": "Suspicious Parent Process Via Sysmon",
        "severity": "HIGH",
        "description": "Abnormal parent-child process chain detected by Sysmon."
    },

    1431: {
        "name": "Encoded PowerShell Via Sysmon",
        "severity": "HIGH",
        "description": "Encoded PowerShell execution observed via Sysmon."
    },

    1432: {
        "name": "Credential Dumping Via Sysmon",
        "severity": "CRITICAL",
        "description": "Credential dumping activity detected via Sysmon telemetry."
    },

    1433: {
        "name": "Suspicious LOLBin Via Sysmon",
        "severity": "HIGH",
        "description": "Living-off-the-land binary usage detected via Sysmon."
    },

    1434: {
        "name": "Network Beaconing Via Sysmon",
        "severity": "HIGH",
        "description": "Periodic network beaconing detected via Sysmon."
    },

    1435: {
        "name": "DNS Tunneling Via Sysmon",
        "severity": "CRITICAL",
        "description": "Potential DNS tunneling activity detected via Sysmon."
    },

    1436: {
        "name": "Registry Persistence Via Sysmon",
        "severity": "HIGH",
        "description": "Persistence through registry modification detected via Sysmon."
    },

    1437: {
        "name": "WMI Persistence Via Sysmon",
        "severity": "CRITICAL",
        "description": "WMI persistence activity detected via Sysmon."
    },

    1438: {
        "name": "Scheduled Task Persistence Via Sysmon",
        "severity": "HIGH",
        "description": "Scheduled task persistence detected via Sysmon."
    },

    1439: {
        "name": "Malicious Service Installation Via Sysmon",
        "severity": "CRITICAL",
        "description": "Malicious service installation detected via Sysmon."
    },

    1440: {
        "name": "Firewall Policy Reset",
        "severity": "HIGH",
        "description": "Firewall policy reset operation detected."
    },

    1441: {
        "name": "Outbound Connection Spike",
        "severity": "MEDIUM",
        "description": "Sudden increase in outbound connections detected."
    },

    1442: {
        "name": "Inbound Connection Spike",
        "severity": "MEDIUM",
        "description": "Abnormal increase in inbound traffic detected."
    },

    1443: {
        "name": "Suspicious Port Binding",
        "severity": "HIGH",
        "description": "Unexpected service bound to sensitive network port."
    },

    1444: {
        "name": "High Entropy DNS Queries",
        "severity": "HIGH",
        "description": "Potential encrypted DNS tunneling behavior detected."
    },

    1445: {
        "name": "Repeated Beacon Retry",
        "severity": "HIGH",
        "description": "Repeated failed beacon communication attempts detected."
    },

    1446: {
        "name": "Encrypted Tunnel Over HTTP",
        "severity": "CRITICAL",
        "description": "Potential encrypted tunneling over HTTP detected."
    },

    1447: {
        "name": "Suspicious TLS Certificate",
        "severity": "HIGH",
        "description": "Suspicious or self-signed TLS certificate observed."
    },

    1448: {
        "name": "JA3 Fingerprint Match",
        "severity": "HIGH",
        "description": "TLS JA3 fingerprint matched known malicious profile."
    },

    1449: {
        "name": "Command Shell Over Network",
        "severity": "CRITICAL",
        "description": "Interactive shell exposed over network connection."
    },

    1450: {
        "name": "Reverse PowerShell Session",
        "severity": "CRITICAL",
        "description": "Reverse PowerShell shell session detected."
    },

        1451: {
        "name": "Meterpreter Payload Activity",
        "severity": "CRITICAL",
        "description": "Potential Meterpreter payload behavior detected."
    },

    1452: {
        "name": "Cobalt Strike Beacon",
        "severity": "CRITICAL",
        "description": "Potential Cobalt Strike beaconing activity detected."
    },

    1453: {
        "name": "Sliver C2 Activity",
        "severity": "CRITICAL",
        "description": "Potential Sliver command-and-control framework activity detected."
    },

    1454: {
        "name": "Mythic Agent Activity",
        "severity": "CRITICAL",
        "description": "Potential Mythic C2 agent behavior detected."
    },

    1455: {
        "name": "Empire Framework Activity",
        "severity": "CRITICAL",
        "description": "Potential PowerShell Empire framework activity detected."
    },

    1456: {
        "name": "Brute Ratel Activity",
        "severity": "CRITICAL",
        "description": "Potential Brute Ratel C4 framework activity detected."
    },

    1457: {
        "name": "AsyncRAT Communication",
        "severity": "CRITICAL",
        "description": "Potential AsyncRAT communication detected."
    },

    1458: {
        "name": "NanoCore RAT Activity",
        "severity": "CRITICAL",
        "description": "Potential NanoCore RAT behavior detected."
    },

    1459: {
        "name": "Quasar RAT Activity",
        "severity": "CRITICAL",
        "description": "Potential Quasar RAT communication detected."
    },

    1460: {
        "name": "Agent Tesla Activity",
        "severity": "CRITICAL",
        "description": "Potential Agent Tesla malware activity detected."
    },

    1461: {
        "name": "RAT Persistence Mechanism",
        "severity": "HIGH",
        "description": "Remote access trojan persistence behavior detected."
    },

    1462: {
        "name": "Credential Phishing Activity",
        "severity": "HIGH",
        "description": "Potential credential phishing behavior detected."
    },

    1463: {
        "name": "Browser Injection Attempt",
        "severity": "CRITICAL",
        "description": "Potential browser injection activity detected."
    },

    1464: {
        "name": "Form Grabbing Activity",
        "severity": "CRITICAL",
        "description": "Potential form-grabbing malware behavior detected."
    },

    1465: {
        "name": "Web Session Hijacking",
        "severity": "CRITICAL",
        "description": "Potential web session hijacking activity detected."
    },

    1466: {
        "name": "Malicious Browser Helper Object",
        "severity": "HIGH",
        "description": "Suspicious browser helper object detected."
    },

    1467: {
        "name": "Credential Replay Attempt",
        "severity": "HIGH",
        "description": "Potential replay attack using stolen credentials detected."
    },

    1468: {
        "name": "Password Dump Utility Execution",
        "severity": "CRITICAL",
        "description": "Password dumping utility execution detected."
    },

    1469: {
        "name": "Mimikatz Activity",
        "severity": "CRITICAL",
        "description": "Potential Mimikatz execution behavior detected."
    },

    1470: {
        "name": "LSA Secret Extraction",
        "severity": "CRITICAL",
        "description": "Potential extraction of LSA secrets detected."
    },

    1471: {
        "name": "Kerberos Ticket Extraction",
        "severity": "CRITICAL",
        "description": "Kerberos ticket extraction activity detected."
    },

    1472: {
        "name": "Credential Cache Access",
        "severity": "HIGH",
        "description": "Credential cache access detected."
    },

    1473: {
        "name": "SAM Backup Extraction",
        "severity": "CRITICAL",
        "description": "Potential SAM backup extraction detected."
    },

    1474: {
        "name": "DPAPI Credential Theft",
        "severity": "CRITICAL",
        "description": "Potential DPAPI credential theft detected."
    },

    1475: {
        "name": "Token Theft Activity",
        "severity": "CRITICAL",
        "description": "Access token theft behavior detected."
    },

    1476: {
        "name": "Privilege Escalation Exploit",
        "severity": "CRITICAL",
        "description": "Potential local privilege escalation exploit detected."
    },

    1477: {
        "name": "UAC Bypass Attempt",
        "severity": "HIGH",
        "description": "User Account Control bypass attempt detected."
    },

    1478: {
        "name": "COM Elevation Abuse",
        "severity": "HIGH",
        "description": "COM object privilege escalation abuse detected."
    },

    1479: {
        "name": "AutoElevate Binary Abuse",
        "severity": "HIGH",
        "description": "AutoElevate Windows binary abuse detected."
    },

    1480: {
        "name": "Bypass Of Protected Process Light",
        "severity": "CRITICAL",
        "description": "Attempt to bypass Protected Process Light detected."
    },

    1481: {
        "name": "Kernel Callback Tampering",
        "severity": "CRITICAL",
        "description": "Potential kernel callback tampering detected."
    },

    1482: {
        "name": "SSDT Hooking Activity",
        "severity": "CRITICAL",
        "description": "System Service Descriptor Table hooking detected."
    },

    1483: {
        "name": "Inline Hooking Detected",
        "severity": "HIGH",
        "description": "Inline API hooking behavior detected."
    },

    1484: {
        "name": "ETW Tampering Activity",
        "severity": "CRITICAL",
        "description": "Event Tracing for Windows tampering detected."
    },

    1485: {
        "name": "Direct Kernel Object Manipulation",
        "severity": "CRITICAL",
        "description": "Potential DKOM rootkit behavior detected."
    },

    1486: {
        "name": "Rootkit Driver Loaded",
        "severity": "CRITICAL",
        "description": "Potential rootkit driver loading detected."
    },

    1487: {
        "name": "Hidden Process Detected",
        "severity": "CRITICAL",
        "description": "Potential hidden process or rootkit activity detected."
    },

    1488: {
        "name": "Hidden Network Connection",
        "severity": "CRITICAL",
        "description": "Hidden or cloaked network connection detected."
    },

    1489: {
        "name": "Unauthorized Kernel Module",
        "severity": "CRITICAL",
        "description": "Unauthorized kernel module detected."
    },

    1490: {
        "name": "Secure Kernel Tampering",
        "severity": "CRITICAL",
        "description": "Potential secure kernel tampering detected."
    },

    1491: {
        "name": "Credential Guard Disabled",
        "severity": "CRITICAL",
        "description": "Windows Credential Guard disabled."
    },

    1492: {
        "name": "Hypervisor Tampering",
        "severity": "CRITICAL",
        "description": "Potential hypervisor tampering activity detected."
    },

    1493: {
        "name": "Virtualization Escape Attempt",
        "severity": "CRITICAL",
        "description": "Potential virtualization escape attempt detected."
    },

    1494: {
        "name": "Container Escape Attempt",
        "severity": "CRITICAL",
        "description": "Potential container breakout activity detected."
    },

    1495: {
        "name": "Docker Socket Abuse",
        "severity": "HIGH",
        "description": "Unauthorized Docker socket access detected."
    },

    1496: {
        "name": "Kubernetes API Abuse",
        "severity": "HIGH",
        "description": "Suspicious Kubernetes API interaction detected."
    },

    1497: {
        "name": "Cloud Metadata Service Access",
        "severity": "HIGH",
        "description": "Unexpected access to cloud metadata service detected."
    },

    1498: {
        "name": "IAM Credential Enumeration",
        "severity": "HIGH",
        "description": "Cloud IAM credential enumeration detected."
    },

    1499: {
        "name": "Unauthorized Cloud Storage Access",
        "severity": "HIGH",
        "description": "Unexpected cloud storage access activity detected."
    },

    1500: {
        "name": "Cloud Secret Extraction",
        "severity": "CRITICAL",
        "description": "Potential extraction of cloud secrets or tokens detected."
    },

    1501: {
        "name": "Malicious Scheduled Reboot",
        "severity": "HIGH",
        "description": "Unexpected scheduled system reboot detected."
    },

    1502: {
        "name": "System Time Tampering",
        "severity": "HIGH",
        "description": "System time modification detected."
    },

    1503: {
        "name": "NTP Manipulation Attempt",
        "severity": "MEDIUM",
        "description": "Potential NTP manipulation activity detected."
    },

    1504: {
        "name": "Anti-Forensics File Wiping",
        "severity": "CRITICAL",
        "description": "Secure file wiping or shredding behavior detected."
    },

    1505: {
        "name": "Timestomping Activity",
        "severity": "HIGH",
        "description": "File timestamp manipulation detected."
    },

    1506: {
        "name": "Log File Deletion",
        "severity": "CRITICAL",
        "description": "Security log file deletion detected."
    },

    1507: {
        "name": "Event Log Corruption",
        "severity": "CRITICAL",
        "description": "Potential event log corruption detected."
    },

    1508: {
        "name": "Shadow Copy Enumeration",
        "severity": "MEDIUM",
        "description": "Volume shadow copy enumeration detected."
    },

    1509: {
        "name": "Backup Catalog Deletion",
        "severity": "HIGH",
        "description": "Backup catalog deletion activity detected."
    },

    1510: {
        "name": "Recovery Partition Modification",
        "severity": "HIGH",
        "description": "System recovery partition modified unexpectedly."
    },

        1511: {
        "name": "DCSync Attack Detected",
        "severity": "CRITICAL",
        "description": "Potential DCSync credential replication attack detected."
    },

    1512: {
        "name": "ZeroLogon Exploitation Attempt",
        "severity": "CRITICAL",
        "description": "Potential ZeroLogon exploitation activity detected."
    },

    1513: {
        "name": "PrintNightmare Exploit Activity",
        "severity": "CRITICAL",
        "description": "Potential PrintNightmare exploitation detected."
    },

    1514: {
        "name": "PetitPotam Attack Activity",
        "severity": "CRITICAL",
        "description": "Potential PetitPotam NTLM relay coercion detected."
    },

    1515: {
        "name": "EternalBlue Exploit Attempt",
        "severity": "CRITICAL",
        "description": "Potential EternalBlue SMB exploit activity detected."
    },

    1516: {
        "name": "SMBGhost Exploit Activity",
        "severity": "CRITICAL",
        "description": "Potential SMBGhost exploitation detected."
    },

    1517: {
        "name": "ProxyShell Exploit Activity",
        "severity": "CRITICAL",
        "description": "Potential Microsoft Exchange ProxyShell exploitation detected."
    },

    1518: {
        "name": "ProxyLogon Exploit Activity",
        "severity": "CRITICAL",
        "description": "Potential Microsoft Exchange ProxyLogon exploitation detected."
    },

    1519: {
        "name": "HiveNightmare Activity",
        "severity": "CRITICAL",
        "description": "Potential HiveNightmare SAM exposure detected."
    },

    1520: {
        "name": "Follina Exploit Activity",
        "severity": "CRITICAL",
        "description": "Potential Follina MSDT exploit activity detected."
    },

    1521: {
        "name": "RDP Brute Force Attack",
        "severity": "CRITICAL",
        "description": "Multiple RDP brute-force authentication attempts detected."
    },

    1522: {
        "name": "PowerShell Empire Beacon",
        "severity": "CRITICAL",
        "description": "PowerShell Empire beaconing behavior detected."
    },

    1523: {
        "name": "Suspicious LSASS Handle Access",
        "severity": "CRITICAL",
        "description": "Suspicious handle access to LSASS process detected."
    },

    1524: {
        "name": "Unauthorized NTDS Dump",
        "severity": "CRITICAL",
        "description": "Potential NTDS.dit credential dump detected."
    },

    1525: {
        "name": "Golden Ticket Forgery",
        "severity": "CRITICAL",
        "description": "Kerberos Golden Ticket forgery behavior detected."
    },

    1526: {
        "name": "Silver Ticket Forgery",
        "severity": "CRITICAL",
        "description": "Kerberos Silver Ticket forgery behavior detected."
    },

    1527: {
        "name": "Kerberoasting Attack",
        "severity": "HIGH",
        "description": "Potential Kerberoasting credential attack detected."
    },

    1528: {
        "name": "AS-REP Roasting Attack",
        "severity": "HIGH",
        "description": "Potential AS-REP Roasting attack activity detected."
    },

    1529: {
        "name": "Mimikatz Credential Theft",
        "severity": "CRITICAL",
        "description": "Credential theft behavior associated with Mimikatz detected."
    },

    1530: {
        "name": "Credential Dumping Via ProcDump",
        "severity": "CRITICAL",
        "description": "Potential LSASS dumping using ProcDump detected."
    },

    1531: {
        "name": "Pass-the-Hash Authentication",
        "severity": "CRITICAL",
        "description": "Pass-the-Hash authentication activity detected."
    },

    1532: {
        "name": "Pass-the-Ticket Authentication",
        "severity": "CRITICAL",
        "description": "Pass-the-Ticket authentication attack detected."
    },

    1533: {
        "name": "Skeleton Key Attack",
        "severity": "CRITICAL",
        "description": "Potential Skeleton Key malware activity detected."
    },

    1534: {
        "name": "DCShadow Replication Attack",
        "severity": "CRITICAL",
        "description": "Potential DCShadow replication attack detected."
    },

    1535: {
        "name": "Ransomware File Encryption",
        "severity": "CRITICAL",
        "description": "Mass file encryption activity indicative of ransomware detected."
    },

    1536: {
        "name": "Shadow Copy Deletion Via VSSAdmin",
        "severity": "CRITICAL",
        "description": "VSSAdmin shadow copy deletion command detected."
    },

    1537: {
        "name": "BCDEdit Recovery Disable",
        "severity": "HIGH",
        "description": "BCDEdit used to disable recovery protections."
    },

    1538: {
        "name": "Safe Mode Boot Manipulation",
        "severity": "HIGH",
        "description": "System boot configuration modified for Safe Mode abuse."
    },

    1539: {
        "name": "Remote Service Execution Via PsExec",
        "severity": "CRITICAL",
        "description": "Remote execution using PsExec detected."
    },

    1540: {
        "name": "WMI Remote Command Execution",
        "severity": "CRITICAL",
        "description": "Remote command execution through WMI detected."
    },

    1541: {
        "name": "WinRM Remote Execution",
        "severity": "HIGH",
        "description": "Remote PowerShell execution via WinRM detected."
    },

    1542: {
        "name": "PowerShell Download And Execute",
        "severity": "CRITICAL",
        "description": "PowerShell downloading and executing remote payload detected."
    },

    1543: {
        "name": "Encoded PowerShell Payload",
        "severity": "CRITICAL",
        "description": "Encoded PowerShell malware payload detected."
    },

    1544: {
        "name": "AMSI Bypass PowerShell",
        "severity": "CRITICAL",
        "description": "PowerShell AMSI bypass behavior detected."
    },

    1545: {
        "name": "Cobalt Strike Named Pipe",
        "severity": "CRITICAL",
        "description": "Cobalt Strike named pipe communication detected."
    },

    1546: {
        "name": "Reflective DLL Injection Attack",
        "severity": "CRITICAL",
        "description": "Reflective DLL injection attack detected."
    },

    1547: {
        "name": "Process Hollowing Attack",
        "severity": "CRITICAL",
        "description": "Process hollowing malware technique detected."
    },

    1548: {
        "name": "Remote Thread Injection Attack",
        "severity": "CRITICAL",
        "description": "Remote thread injection behavior detected."
    },

    1549: {
        "name": "Syscall Unhooking Attempt",
        "severity": "HIGH",
        "description": "Direct syscall or API unhooking activity detected."
    },

    1550: {
        "name": "ETW Bypass Attempt",
        "severity": "CRITICAL",
        "description": "Event Tracing for Windows bypass attempt detected."
    },

    1551: {
        "name": "Sysmon Tampering Attempt",
        "severity": "CRITICAL",
        "description": "Potential Sysmon service tampering detected."
    },

    1552: {
        "name": "Defender Tampering Attempt",
        "severity": "CRITICAL",
        "description": "Microsoft Defender tampering behavior detected."
    },

    1553: {
        "name": "Security Tool Disable Attempt",
        "severity": "CRITICAL",
        "description": "Attempt to disable endpoint security tools detected."
    },

    1554: {
        "name": "Suspicious DNS Tunneling",
        "severity": "CRITICAL",
        "description": "Potential DNS tunneling command-and-control activity detected."
    },

    1555: {
        "name": "Command And Control Beaconing",
        "severity": "CRITICAL",
        "description": "Beaconing traffic consistent with command-and-control detected."
    },

    1556: {
        "name": "Data Exfiltration Over HTTPS",
        "severity": "CRITICAL",
        "description": "Potential data exfiltration over encrypted HTTPS channel detected."
    },

    1557: {
        "name": "TOR Communication Activity",
        "severity": "HIGH",
        "description": "Connection to TOR anonymity network detected."
    },

    1558: {
        "name": "Reverse Shell PowerShell",
        "severity": "CRITICAL",
        "description": "PowerShell reverse shell activity detected."
    },

    1559: {
        "name": "Persistence Via Registry Run Keys",
        "severity": "HIGH",
        "description": "Registry Run key persistence mechanism detected."
    },

    1560: {
        "name": "WMI Persistence Mechanism",
        "severity": "HIGH",
        "description": "Persistence through WMI event subscription detected."
    },

        1561: {
        "name": "Scheduled Task Persistence Attack",
        "severity": "HIGH",
        "description": "Persistence established through scheduled task creation."
    },

    1562: {
        "name": "Startup Folder Persistence",
        "severity": "HIGH",
        "description": "Persistence established using startup folder."
    },

    1563: {
        "name": "Service-Based Persistence",
        "severity": "CRITICAL",
        "description": "Malicious persistence through Windows service detected."
    },

    1564: {
        "name": "DLL Search Order Hijacking Attack",
        "severity": "HIGH",
        "description": "DLL search order hijacking technique detected."
    },

    1565: {
        "name": "Browser Credential Dumping",
        "severity": "CRITICAL",
        "description": "Browser credential extraction activity detected."
    },

    1566: {
        "name": "Session Cookie Theft",
        "severity": "CRITICAL",
        "description": "Potential browser session cookie theft detected."
    },

    1567: {
        "name": "Unauthorized VPN Tunnel",
        "severity": "HIGH",
        "description": "Unexpected outbound VPN tunneling detected."
    },

    1568: {
        "name": "Lateral Movement Via SMB",
        "severity": "CRITICAL",
        "description": "Potential SMB-based lateral movement detected."
    },

    1569: {
        "name": "SMB Admin Share Abuse",
        "severity": "HIGH",
        "description": "Administrative SMB share abuse detected."
    },

    1570: {
        "name": "NTLM Relay Authentication",
        "severity": "CRITICAL",
        "description": "NTLM relay authentication attack detected."
    },

    1571: {
        "name": "LLMNR Poisoning Attack",
        "severity": "CRITICAL",
        "description": "LLMNR/NBT-NS poisoning behavior detected."
    },

    1572: {
        "name": "ARP Spoofing Attack",
        "severity": "CRITICAL",
        "description": "ARP spoofing or man-in-the-middle attack detected."
    },

    1573: {
        "name": "Unauthorized RDP Session",
        "severity": "HIGH",
        "description": "Unexpected Remote Desktop session detected."
    },

    1574: {
        "name": "RDP Session Hijacking Attack",
        "severity": "CRITICAL",
        "description": "Potential Remote Desktop session hijacking detected."
    },

    1575: {
        "name": "Remote Assistance Abuse",
        "severity": "HIGH",
        "description": "Potential abuse of Windows Remote Assistance detected."
    },

    1576: {
        "name": "Excessive Failed SMB Logins",
        "severity": "HIGH",
        "description": "Multiple failed SMB authentication attempts detected."
    },

    1577: {
        "name": "Password Spraying Campaign",
        "severity": "CRITICAL",
        "description": "Password spraying attack campaign detected."
    },

    1578: {
        "name": "Account Lockout Spike",
        "severity": "HIGH",
        "description": "Spike in account lockouts detected."
    },

    1579: {
        "name": "Suspicious GeoIP Login",
        "severity": "HIGH",
        "description": "Authentication from suspicious geographic region detected."
    },

    1580: {
        "name": "Impossible Travel Authentication",
        "severity": "HIGH",
        "description": "Impossible travel login pattern detected."
    },

    1581: {
        "name": "Dormant Privileged Account Login",
        "severity": "CRITICAL",
        "description": "Dormant privileged account used for authentication."
    },

    1582: {
        "name": "New Admin Account Creation",
        "severity": "CRITICAL",
        "description": "New administrative account created unexpectedly."
    },

    1583: {
        "name": "Domain Admin Group Modification",
        "severity": "CRITICAL",
        "description": "Domain Admins group membership modified."
    },

    1584: {
        "name": "Privilege Escalation Via Token Theft",
        "severity": "CRITICAL",
        "description": "Privilege escalation using stolen tokens detected."
    },

    1585: {
        "name": "Malicious GPO Modification",
        "severity": "CRITICAL",
        "description": "Unauthorized Group Policy modification detected."
    },

    1586: {
        "name": "AdminSDHolder Persistence",
        "severity": "CRITICAL",
        "description": "Persistence through AdminSDHolder modification detected."
    },

    1587: {
        "name": "Unauthorized SYSVOL Modification",
        "severity": "HIGH",
        "description": "Unexpected SYSVOL share modification detected."
    },

    1588: {
        "name": "ADCS Certificate Abuse",
        "severity": "CRITICAL",
        "description": "Abuse of Active Directory Certificate Services detected."
    },

    1589: {
        "name": "Certificate Enrollment Exploitation",
        "severity": "CRITICAL",
        "description": "Malicious certificate enrollment activity detected."
    },

    1590: {
        "name": "Shadow Credentials Attack",
        "severity": "CRITICAL",
        "description": "Potential shadow credentials attack detected."
    },

    1591: {
        "name": "SID History Manipulation",
        "severity": "CRITICAL",
        "description": "SID History manipulation activity detected."
    },

    1592: {
        "name": "Unconstrained Delegation Abuse",
        "severity": "CRITICAL",
        "description": "Unconstrained delegation exploitation detected."
    },

    1593: {
        "name": "Constrained Delegation Abuse",
        "severity": "CRITICAL",
        "description": "Constrained delegation exploitation detected."
    },

    1594: {
        "name": "Resource Delegation Abuse",
        "severity": "CRITICAL",
        "description": "Resource-based constrained delegation abuse detected."
    },

    1595: {
        "name": "Wiper Malware Activity",
        "severity": "CRITICAL",
        "description": "Potential destructive wiper malware behavior detected."
    },

    1596: {
        "name": "Disk Destruction Activity",
        "severity": "CRITICAL",
        "description": "Potential destructive disk overwrite activity detected."
    },

    1597: {
        "name": "MBR Modification Attempt",
        "severity": "CRITICAL",
        "description": "Master Boot Record modification detected."
    },

    1598: {
        "name": "Bootkit Installation",
        "severity": "CRITICAL",
        "description": "Potential bootkit installation detected."
    },

    1599: {
        "name": "UEFI Rootkit Activity",
        "severity": "CRITICAL",
        "description": "Potential UEFI rootkit behavior detected."
    },

    1600: {
        "name": "Kernel Rootkit Installation",
        "severity": "CRITICAL",
        "description": "Kernel-level rootkit installation detected."
    },

    1601: {
        "name": "Credential Guard Bypass",
        "severity": "CRITICAL",
        "description": "Attempt to bypass Credential Guard protections detected."
    },

    1602: {
        "name": "Secure Boot Tampering",
        "severity": "CRITICAL",
        "description": "Secure Boot tampering activity detected."
    },

    1603: {
        "name": "TPM Manipulation Attempt",
        "severity": "CRITICAL",
        "description": "Trusted Platform Module manipulation detected."
    },

    1604: {
        "name": "Hypervisor Rootkit Activity",
        "severity": "CRITICAL",
        "description": "Potential hypervisor-level rootkit detected."
    },

    1605: {
        "name": "Cloud Token Theft",
        "severity": "CRITICAL",
        "description": "Cloud access token theft activity detected."
    },

    1606: {
        "name": "Azure AD Enumeration",
        "severity": "HIGH",
        "description": "Azure Active Directory enumeration activity detected."
    },

    1607: {
        "name": "OAuth Application Abuse",
        "severity": "CRITICAL",
        "description": "Malicious OAuth application behavior detected."
    },

    1608: {
        "name": "Suspicious SAML Authentication",
        "severity": "CRITICAL",
        "description": "Suspicious SAML authentication activity detected."
    },

    1609: {
        "name": "Golden SAML Attack",
        "severity": "CRITICAL",
        "description": "Golden SAML attack behavior detected."
    },

    1610: {
        "name": "Cloud Privilege Escalation",
        "severity": "CRITICAL",
        "description": "Cloud privilege escalation activity detected."
    },

        1611: {
        "name": "Malicious OAuth Consent Grant",
        "severity": "CRITICAL",
        "description": "Suspicious OAuth consent grant detected."
    },

    1612: {
        "name": "Azure Managed Identity Abuse",
        "severity": "CRITICAL",
        "description": "Potential abuse of Azure managed identities detected."
    },

    1613: {
        "name": "AWS Metadata Credential Theft",
        "severity": "CRITICAL",
        "description": "Attempt to retrieve AWS instance metadata credentials detected."
    },

    1614: {
        "name": "GCP Service Account Abuse",
        "severity": "HIGH",
        "description": "Potential abuse of Google Cloud service accounts detected."
    },

    1615: {
        "name": "Cloud Storage Mass Download",
        "severity": "CRITICAL",
        "description": "Massive cloud storage download activity detected."
    },

    1616: {
        "name": "Cloud Snapshot Exfiltration",
        "severity": "CRITICAL",
        "description": "Cloud snapshot export or exfiltration detected."
    },

    1617: {
        "name": "Suspicious IAM Policy Change",
        "severity": "CRITICAL",
        "description": "Unexpected IAM permission modification detected."
    },

    1618: {
        "name": "Cross-Tenant Authentication",
        "severity": "HIGH",
        "description": "Unexpected cross-tenant authentication activity detected."
    },

    1619: {
        "name": "Mass Secret Enumeration",
        "severity": "HIGH",
        "description": "Large-scale secret or key enumeration detected."
    },

    1620: {
        "name": "Vault Credential Extraction",
        "severity": "CRITICAL",
        "description": "Credential extraction from secrets vault detected."
    },

    1621: {
        "name": "Container Privilege Escalation",
        "severity": "CRITICAL",
        "description": "Container privilege escalation activity detected."
    },

    1622: {
        "name": "Kubernetes Secret Access",
        "severity": "HIGH",
        "description": "Unauthorized Kubernetes secret access detected."
    },

    1623: {
        "name": "Kubernetes Exec Abuse",
        "severity": "HIGH",
        "description": "Suspicious kubectl exec activity detected."
    },

    1624: {
        "name": "Container Image Tampering",
        "severity": "HIGH",
        "description": "Container image modification or tampering detected."
    },

    1625: {
        "name": "Docker Privileged Container",
        "severity": "HIGH",
        "description": "Privileged Docker container execution detected."
    },

    1626: {
        "name": "Container Escape Exploit",
        "severity": "CRITICAL",
        "description": "Potential container escape exploit detected."
    },

    1627: {
        "name": "Suspicious Cron Job Persistence",
        "severity": "HIGH",
        "description": "Potential malicious cron job persistence detected."
    },

    1628: {
        "name": "Unauthorized SSH Key Added",
        "severity": "HIGH",
        "description": "Unexpected SSH authorized key addition detected."
    },

    1629: {
        "name": "SSH Agent Hijacking",
        "severity": "CRITICAL",
        "description": "Potential SSH agent hijacking detected."
    },

    1630: {
        "name": "Bash History Tampering",
        "severity": "HIGH",
        "description": "Bash history deletion or tampering detected."
    },

    1631: {
        "name": "Suspicious Sudo Usage",
        "severity": "HIGH",
        "description": "Abnormal sudo command execution detected."
    },

    1632: {
        "name": "Linux Capability Abuse",
        "severity": "CRITICAL",
        "description": "Potential abuse of Linux capabilities detected."
    },

    1633: {
        "name": "LD_PRELOAD Injection",
        "severity": "CRITICAL",
        "description": "LD_PRELOAD injection technique detected."
    },

    1634: {
        "name": "Linux Kernel Module Injection",
        "severity": "CRITICAL",
        "description": "Malicious Linux kernel module loading detected."
    },

    1635: {
        "name": "Hidden Linux Process",
        "severity": "CRITICAL",
        "description": "Potential hidden Linux process detected."
    },

    1636: {
        "name": "Linux Rootkit Activity",
        "severity": "CRITICAL",
        "description": "Linux rootkit behavior detected."
    },

    1637: {
        "name": "Unauthorized Chmod 777",
        "severity": "HIGH",
        "description": "Suspicious chmod 777 permission assignment detected."
    },

    1638: {
        "name": "Sensitive File Permission Change",
        "severity": "HIGH",
        "description": "Critical file permission modification detected."
    },

    1639: {
        "name": "Unauthorized SUID Binary",
        "severity": "CRITICAL",
        "description": "Unexpected SUID binary creation detected."
    },

    1640: {
        "name": "GTFOBins Abuse",
        "severity": "CRITICAL",
        "description": "GTFOBins privilege escalation technique detected."
    },

    1641: {
        "name": "Web Shell Deployment",
        "severity": "CRITICAL",
        "description": "Potential web shell deployment detected."
    },

    1642: {
        "name": "Malicious PHP Execution",
        "severity": "HIGH",
        "description": "Suspicious PHP execution activity detected."
    },

    1643: {
        "name": "JSP Web Shell Activity",
        "severity": "CRITICAL",
        "description": "Potential JSP web shell execution detected."
    },

    1644: {
        "name": "ASPX Web Shell Activity",
        "severity": "CRITICAL",
        "description": "Potential ASPX web shell execution detected."
    },

    1645: {
        "name": "Apache Configuration Tampering",
        "severity": "HIGH",
        "description": "Apache configuration modification detected."
    },

    1646: {
        "name": "Nginx Configuration Tampering",
        "severity": "HIGH",
        "description": "Nginx configuration modification detected."
    },

    1647: {
        "name": "SQL Injection Attempt",
        "severity": "CRITICAL",
        "description": "Potential SQL injection attack detected."
    },

    1648: {
        "name": "Command Injection Attempt",
        "severity": "CRITICAL",
        "description": "Potential command injection attack detected."
    },

    1649: {
        "name": "Local File Inclusion Attack",
        "severity": "HIGH",
        "description": "Potential local file inclusion attack detected."
    },

    1650: {
        "name": "Remote File Inclusion Attack",
        "severity": "CRITICAL",
        "description": "Potential remote file inclusion attack detected."
    },

    1651: {
        "name": "Path Traversal Attempt",
        "severity": "HIGH",
        "description": "Directory traversal attack attempt detected."
    },

    1652: {
        "name": "Server-Side Request Forgery",
        "severity": "CRITICAL",
        "description": "Potential SSRF attack activity detected."
    },

    1653: {
        "name": "XXE Injection Attempt",
        "severity": "HIGH",
        "description": "XML External Entity injection attempt detected."
    },

    1654: {
        "name": "Deserialization Exploit Attempt",
        "severity": "CRITICAL",
        "description": "Potential insecure deserialization exploit detected."
    },

    1655: {
        "name": "Suspicious File Upload",
        "severity": "HIGH",
        "description": "Potential malicious file upload detected."
    },

    1656: {
        "name": "Web Application Enumeration",
        "severity": "MEDIUM",
        "description": "Web application enumeration activity detected."
    },

    1657: {
        "name": "Credential Stuffing Against Web Portal",
        "severity": "CRITICAL",
        "description": "Credential stuffing attack against web application detected."
    },

    1658: {
        "name": "Suspicious API Abuse",
        "severity": "HIGH",
        "description": "Unexpected API abuse or excessive requests detected."
    },

    1659: {
        "name": "Session Fixation Attempt",
        "severity": "HIGH",
        "description": "Potential session fixation attack detected."
    },

    1660: {
        "name": "JWT Token Forgery",
        "severity": "CRITICAL",
        "description": "Potential JWT token forgery activity detected."
    },

        1661: {
        "name": "Suspicious OAuth Token Usage",
        "severity": "HIGH",
        "description": "Abnormal OAuth token usage detected."
    },

    1662: {
        "name": "Mass Authentication Failures",
        "severity": "HIGH",
        "description": "Large number of authentication failures detected."
    },

    1663: {
        "name": "Password Reset Flood",
        "severity": "MEDIUM",
        "description": "Excessive password reset requests detected."
    },

    1664: {
        "name": "Multiple MFA Failures",
        "severity": "HIGH",
        "description": "Repeated multi-factor authentication failures detected."
    },

    1665: {
        "name": "MFA Fatigue Attack",
        "severity": "CRITICAL",
        "description": "Potential MFA fatigue or push bombing attack detected."
    },

    1666: {
        "name": "Suspicious Device Enrollment",
        "severity": "HIGH",
        "description": "Unexpected device enrollment activity detected."
    },

    1667: {
        "name": "BYOVD Attack Activity",
        "severity": "CRITICAL",
        "description": "Bring Your Own Vulnerable Driver attack detected."
    },

    1668: {
        "name": "Unsigned PowerShell Module",
        "severity": "HIGH",
        "description": "Unsigned PowerShell module loaded."
    },

    1669: {
        "name": "PowerShell Profile Persistence",
        "severity": "HIGH",
        "description": "Persistence through PowerShell profile modification detected."
    },

    1670: {
        "name": "Encoded VBScript Payload",
        "severity": "HIGH",
        "description": "Encoded VBScript malware payload detected."
    },

    1671: {
        "name": "Suspicious HTA Download",
        "severity": "HIGH",
        "description": "Remote HTA payload download detected."
    },

    1672: {
        "name": "ClickOnce Abuse",
        "severity": "MEDIUM",
        "description": "Potential malicious ClickOnce deployment detected."
    },

    1673: {
        "name": "OneDrive Mass File Activity",
        "severity": "HIGH",
        "description": "Mass OneDrive file operations detected."
    },

    1674: {
        "name": "SharePoint Data Exfiltration",
        "severity": "CRITICAL",
        "description": "Potential SharePoint data exfiltration detected."
    },

    1675: {
        "name": "Teams External File Delivery",
        "severity": "MEDIUM",
        "description": "External file delivery via Microsoft Teams detected."
    },

    1676: {
        "name": "Outlook Rule Manipulation",
        "severity": "HIGH",
        "description": "Suspicious Outlook mail rule modification detected."
    },

    1677: {
        "name": "Email Forwarding Rule Creation",
        "severity": "HIGH",
        "description": "Automatic email forwarding rule created."
    },

    1678: {
        "name": "Mailbox Permission Escalation",
        "severity": "HIGH",
        "description": "Mailbox permission escalation detected."
    },

    1679: {
        "name": "Suspicious OAuth Mail Access",
        "severity": "HIGH",
        "description": "OAuth application accessed mailbox unexpectedly."
    },

    1680: {
        "name": "Mass Email Deletion",
        "severity": "HIGH",
        "description": "Large-scale mailbox deletion activity detected."
    },

    1681: {
        "name": "Impossible MFA Sequence",
        "severity": "HIGH",
        "description": "Impossible sequence of MFA approvals detected."
    },

    1682: {
        "name": "Authentication From Anonymous Proxy",
        "severity": "HIGH",
        "description": "Login through anonymous proxy or VPN detected."
    },

    1683: {
        "name": "Disposable Email Usage",
        "severity": "MEDIUM",
        "description": "Disposable email service usage detected."
    },

    1684: {
        "name": "Cloud App Consent Abuse",
        "severity": "CRITICAL",
        "description": "Malicious cloud application consent activity detected."
    },

    1685: {
        "name": "Unusual Service Principal Activity",
        "severity": "HIGH",
        "description": "Unexpected service principal behavior detected."
    },

    1686: {
        "name": "Azure Automation Abuse",
        "severity": "HIGH",
        "description": "Potential abuse of Azure automation detected."
    },

    1687: {
        "name": "Suspicious Intune Policy Change",
        "severity": "HIGH",
        "description": "Unexpected Microsoft Intune policy modification detected."
    },

    1688: {
        "name": "Conditional Access Policy Disabled",
        "severity": "CRITICAL",
        "description": "Conditional access protection disabled."
    },

    1689: {
        "name": "Cloud Security Alert Suppression",
        "severity": "CRITICAL",
        "description": "Cloud security alert suppression detected."
    },

    1690: {
        "name": "Mass VM Creation",
        "severity": "HIGH",
        "description": "Large-scale virtual machine provisioning detected."
    },

    1691: {
        "name": "Crypto Mining Workload",
        "severity": "HIGH",
        "description": "Potential cloud cryptocurrency mining workload detected."
    },

    1692: {
        "name": "Cloud Firewall Rule Exposure",
        "severity": "CRITICAL",
        "description": "Cloud firewall opened to public internet."
    },

    1693: {
        "name": "Public Storage Bucket Exposure",
        "severity": "CRITICAL",
        "description": "Publicly accessible storage bucket detected."
    },

    1694: {
        "name": "Sensitive Blob Enumeration",
        "severity": "HIGH",
        "description": "Enumeration of sensitive cloud storage blobs detected."
    },

    1695: {
        "name": "Serverless Function Abuse",
        "severity": "HIGH",
        "description": "Potential malicious serverless function execution detected."
    },

    1696: {
        "name": "Cloud Resource Deletion",
        "severity": "HIGH",
        "description": "Critical cloud resource deletion detected."
    },

    1697: {
        "name": "DNS Sinkhole Match",
        "severity": "HIGH",
        "description": "Connection matched known DNS sinkhole domain."
    },

    1698: {
        "name": "Malware Sandbox Evasion",
        "severity": "HIGH",
        "description": "Malware sandbox evasion behavior detected."
    },

    1699: {
        "name": "Suspicious Entropy In File",
        "severity": "MEDIUM",
        "description": "High entropy file potentially indicating packing or encryption detected."
    },

    1700: {
        "name": "Packed Executable Detected",
        "severity": "MEDIUM",
        "description": "Packed executable binary detected."
    },

    1701: {
        "name": "PE Header Tampering",
        "severity": "HIGH",
        "description": "Portable Executable header tampering detected."
    },

    1702: {
        "name": "Self-Modifying Code",
        "severity": "CRITICAL",
        "description": "Self-modifying code behavior detected."
    },

    1703: {
        "name": "Anti-VM Technique Detected",
        "severity": "HIGH",
        "description": "Anti-virtualization technique detected."
    },

    1704: {
        "name": "Anti-Debugging Technique",
        "severity": "HIGH",
        "description": "Anti-debugging behavior detected."
    },

    1705: {
        "name": "Heap Spray Activity",
        "severity": "HIGH",
        "description": "Potential heap spray exploitation technique detected."
    },

    1706: {
        "name": "ROP Chain Exploitation",
        "severity": "CRITICAL",
        "description": "Return-Oriented Programming exploitation detected."
    },

    1707: {
        "name": "Shellcode Decoder Stub",
        "severity": "HIGH",
        "description": "Shellcode decoder stub behavior detected."
    },

    1708: {
        "name": "Suspicious Memory Allocation",
        "severity": "HIGH",
        "description": "Executable memory allocation activity detected."
    },

    1709: {
        "name": "RWX Memory Region Created",
        "severity": "CRITICAL",
        "description": "Read-write-execute memory region creation detected."
    },

    1710: {
        "name": "Executable Written To Memory",
        "severity": "CRITICAL",
        "description": "Executable payload written directly into memory."
    },

    1711: {
        "name": "Direct Syscall Execution",
        "severity": "HIGH",
        "description": "Direct syscall execution bypassing APIs detected."
    },

    1712: {
        "name": "Process Doppelgänging",
        "severity": "CRITICAL",
        "description": "Process Doppelgänging attack technique detected."
    },

    1713: {
        "name": "AtomBombing Technique",
        "severity": "CRITICAL",
        "description": "AtomBombing code injection technique detected."
    },

    1714: {
        "name": "Herpaderping Technique",
        "severity": "CRITICAL",
        "description": "Process Herpaderping evasion technique detected."
    },

    1715: {
        "name": "Module Stomping Attack",
        "severity": "CRITICAL",
        "description": "Module stomping injection technique detected."
    },

    1716: {
        "name": "Transacted Hollowing",
        "severity": "CRITICAL",
        "description": "Transacted process hollowing activity detected."
    },

    1717: {
        "name": "PPID Spoofing Attack",
        "severity": "HIGH",
        "description": "Parent Process ID spoofing detected."
    },

    1718: {
        "name": "Execution From UNC Path",
        "severity": "HIGH",
        "description": "Executable launched from remote UNC network path."
    },

    1719: {
        "name": "Hidden Scheduled Task",
        "severity": "HIGH",
        "description": "Hidden scheduled task detected."
    },

    1720: {
        "name": "Autorun Registry Abuse",
        "severity": "HIGH",
        "description": "Autorun registry persistence detected."
    },

        1721: {
        "name": "Startup Approved Registry Tampering",
        "severity": "HIGH",
        "description": "StartupApproved registry keys modified unexpectedly."
    },

    1722: {
        "name": "Image File Execution Options Abuse",
        "severity": "CRITICAL",
        "description": "IFEO debugger hijacking persistence detected."
    },

    1723: {
        "name": "SilentProcessExit Persistence",
        "severity": "HIGH",
        "description": "SilentProcessExit registry persistence detected."
    },

    1724: {
        "name": "Accessibility Backdoor Modification",
        "severity": "CRITICAL",
        "description": "Accessibility executable replacement detected."
    },

    1725: {
        "name": "Malicious Screensaver Execution",
        "severity": "HIGH",
        "description": "Potential malicious screensaver binary executed."
    },

    1726: {
        "name": "COM Object Persistence",
        "severity": "HIGH",
        "description": "COM object persistence mechanism detected."
    },

    1727: {
        "name": "Explorer Shell Extension Abuse",
        "severity": "HIGH",
        "description": "Suspicious Explorer shell extension detected."
    },

    1728: {
        "name": "Browser Extension Sideloading",
        "severity": "HIGH",
        "description": "Unauthorized browser extension sideloading detected."
    },

    1729: {
        "name": "Malicious Chrome Extension",
        "severity": "HIGH",
        "description": "Potential malicious Chrome extension detected."
    },

    1730: {
        "name": "Malicious Edge Extension",
        "severity": "HIGH",
        "description": "Potential malicious Microsoft Edge extension detected."
    },

    1731: {
        "name": "Firefox Profile Tampering",
        "severity": "MEDIUM",
        "description": "Firefox profile modification activity detected."
    },

    1732: {
        "name": "Credential Harvesting Page",
        "severity": "CRITICAL",
        "description": "Potential credential harvesting webpage detected."
    },

    1733: {
        "name": "Clipboard Cryptocurrency Hijacking",
        "severity": "HIGH",
        "description": "Clipboard cryptocurrency address replacement detected."
    },

    1734: {
        "name": "Suspicious QR Code Delivery",
        "severity": "MEDIUM",
        "description": "Potential malicious QR code payload delivery detected."
    },

    1735: {
        "name": "Drive-By Download Activity",
        "severity": "HIGH",
        "description": "Drive-by browser download behavior detected."
    },

    1736: {
        "name": "Malicious Browser Redirect",
        "severity": "MEDIUM",
        "description": "Suspicious browser redirection detected."
    },

    1737: {
        "name": "SEO Poisoning Access",
        "severity": "MEDIUM",
        "description": "Potential SEO poisoning website access detected."
    },

    1738: {
        "name": "Suspicious PDF Execution",
        "severity": "HIGH",
        "description": "Potential malicious PDF exploit activity detected."
    },

    1739: {
        "name": "Macro-Based Malware Delivery",
        "severity": "HIGH",
        "description": "Macro-enabled malware delivery detected."
    },

    1740: {
        "name": "Office Template Injection",
        "severity": "HIGH",
        "description": "Remote Office template injection detected."
    },

    1741: {
        "name": "Excel 4.0 Macro Execution",
        "severity": "CRITICAL",
        "description": "Excel 4.0 macro execution activity detected."
    },

    1742: {
        "name": "DDE Exploitation Attempt",
        "severity": "HIGH",
        "description": "Dynamic Data Exchange exploitation detected."
    },

    1743: {
        "name": "OLE Object Exploit",
        "severity": "HIGH",
        "description": "Suspicious embedded OLE object execution detected."
    },

    1744: {
        "name": "MSDT Exploit Invocation",
        "severity": "CRITICAL",
        "description": "MSDT diagnostic tool exploitation detected."
    },

    1745: {
        "name": "Remote Template Injection",
        "severity": "HIGH",
        "description": "Remote document template injection detected."
    },

    1746: {
        "name": "Suspicious ISO Attachment",
        "severity": "MEDIUM",
        "description": "Potential malicious ISO attachment accessed."
    },

    1747: {
        "name": "LNK File Phishing Payload",
        "severity": "HIGH",
        "description": "Malicious shortcut phishing payload detected."
    },

    1748: {
        "name": "HTML Smuggling Attack",
        "severity": "HIGH",
        "description": "HTML smuggling malware delivery detected."
    },

    1749: {
        "name": "Java Archive Exploit",
        "severity": "HIGH",
        "description": "Suspicious Java archive execution detected."
    },

    1750: {
        "name": "Malicious MSI Installer",
        "severity": "HIGH",
        "description": "Potential malicious MSI installer execution detected."
    },

    1751: {
        "name": "Remote MSI Deployment",
        "severity": "HIGH",
        "description": "Remote MSI deployment activity detected."
    },

    1752: {
        "name": "Installer Repair Abuse",
        "severity": "HIGH",
        "description": "Windows Installer repair abuse detected."
    },

    1753: {
        "name": "Executable Masquerading As Document",
        "severity": "HIGH",
        "description": "Executable disguised as document file detected."
    },

    1754: {
        "name": "Double Extension File Execution",
        "severity": "HIGH",
        "description": "Double-extension executable file detected."
    },

    1755: {
        "name": "Alternate Data Stream Payload",
        "severity": "HIGH",
        "description": "Payload stored in NTFS Alternate Data Stream detected."
    },

    1756: {
        "name": "Hidden File Attribute Abuse",
        "severity": "MEDIUM",
        "description": "Suspicious hidden/system file attribute usage detected."
    },

    1757: {
        "name": "Suspicious Compression Archive",
        "severity": "MEDIUM",
        "description": "Potential malware-packed archive detected."
    },

    1758: {
        "name": "Password Protected Archive Delivery",
        "severity": "MEDIUM",
        "description": "Password-protected archive delivery detected."
    },

    1759: {
        "name": "RAR Utility Abuse",
        "severity": "MEDIUM",
        "description": "Suspicious use of RAR utility detected."
    },

    1760: {
        "name": "7Zip Data Staging",
        "severity": "HIGH",
        "description": "Data staging using 7Zip compression detected."
    },

    1761: {
        "name": "WinRAR Archive Exfiltration",
        "severity": "HIGH",
        "description": "Compressed archive prepared for exfiltration detected."
    },

    1762: {
        "name": "Mass File Compression",
        "severity": "HIGH",
        "description": "Large-scale file compression activity detected."
    },

    1763: {
        "name": "Sensitive Directory Enumeration",
        "severity": "MEDIUM",
        "description": "Enumeration of sensitive directories detected."
    },

    1764: {
        "name": "Shadow Copy Access Attempt",
        "severity": "HIGH",
        "description": "Unexpected access to shadow copy storage detected."
    },

    1765: {
        "name": "Registry Hive Export",
        "severity": "HIGH",
        "description": "Registry hive export activity detected."
    },

    1766: {
        "name": "Offline Credential Extraction",
        "severity": "CRITICAL",
        "description": "Offline credential extraction attempt detected."
    },

    1767: {
        "name": "LSASS Clone Process",
        "severity": "CRITICAL",
        "description": "LSASS process cloning activity detected."
    },

    1768: {
        "name": "PPL Bypass Attempt",
        "severity": "CRITICAL",
        "description": "Protected Process Light bypass attempt detected."
    },

    1769: {
        "name": "Malicious ETW Provider",
        "severity": "HIGH",
        "description": "Suspicious ETW provider manipulation detected."
    },

    1770: {
        "name": "Event Provider Unregistration",
        "severity": "HIGH",
        "description": "Security event provider unregistration detected."
    },

    1771: {
        "name": "Windows Service DLL Hijacking",
        "severity": "HIGH",
        "description": "Service DLL hijacking technique detected."
    },

    1772: {
        "name": "Orphaned Service Abuse",
        "severity": "MEDIUM",
        "description": "Potential orphaned service exploitation detected."
    },

    1773: {
        "name": "Driver Signature Enforcement Disabled",
        "severity": "CRITICAL",
        "description": "Driver signature enforcement disabled."
    },

    1774: {
        "name": "Test Signing Mode Enabled",
        "severity": "HIGH",
        "description": "Windows test-signing mode enabled."
    },

    1775: {
        "name": "Kernel Debugging Enabled",
        "severity": "HIGH",
        "description": "Kernel debugging configuration enabled."
    },

    1776: {
        "name": "Unauthorized Hyper-V Modification",
        "severity": "HIGH",
        "description": "Unexpected Hyper-V configuration modification detected."
    },

    1777: {
        "name": "VM Snapshot Tampering",
        "severity": "HIGH",
        "description": "Virtual machine snapshot tampering detected."
    },

    1778: {
        "name": "Snapshot Rollback Abuse",
        "severity": "HIGH",
        "description": "Suspicious VM snapshot rollback detected."
    },

    1779: {
        "name": "Malicious USB HID Device",
        "severity": "HIGH",
        "description": "Potential malicious USB HID device detected."
    },

    1780: {
        "name": "Rubber Ducky Attack",
        "severity": "CRITICAL",
        "description": "USB Rubber Ducky style keystroke injection detected."
    },

        1781: {
        "name": "BadUSB Firmware Attack",
        "severity": "CRITICAL",
        "description": "Potential BadUSB firmware manipulation detected."
    },

    1782: {
        "name": "Unauthorized Smart Card Usage",
        "severity": "HIGH",
        "description": "Unexpected smart card authentication activity detected."
    },

    1783: {
        "name": "Hardware Security Key Removal",
        "severity": "MEDIUM",
        "description": "Hardware security token removal detected."
    },

    1784: {
        "name": "TPM Ownership Change",
        "severity": "HIGH",
        "description": "Trusted Platform Module ownership modification detected."
    },

    1785: {
        "name": "BitLocker Recovery Key Exposure",
        "severity": "CRITICAL",
        "description": "Potential BitLocker recovery key exposure detected."
    },

    1786: {
        "name": "Secure Credential Backup Export",
        "severity": "HIGH",
        "description": "Credential backup export activity detected."
    },

    1787: {
        "name": "Unauthorized Password Vault Access",
        "severity": "CRITICAL",
        "description": "Unexpected password vault access detected."
    },

    1788: {
        "name": "Password Manager Database Theft",
        "severity": "CRITICAL",
        "description": "Potential password manager database theft detected."
    },

    1789: {
        "name": "Memory Resident Malware",
        "severity": "CRITICAL",
        "description": "Fileless or memory-resident malware activity detected."
    },

    1790: {
        "name": "Fileless PowerShell Attack",
        "severity": "CRITICAL",
        "description": "Fileless PowerShell-based attack detected."
    },

    1791: {
        "name": "Living-Off-The-Land Binary Chain",
        "severity": "CRITICAL",
        "description": "Chained LOLBin execution behavior detected."
    },

    1792: {
        "name": "Remote Payload Injection",
        "severity": "CRITICAL",
        "description": "Remote payload injection into trusted process detected."
    },

    1793: {
        "name": "Multi-Stage Malware Loader",
        "severity": "CRITICAL",
        "description": "Multi-stage malware loader activity detected."
    },

    1794: {
        "name": "Polymorphic Malware Behavior",
        "severity": "CRITICAL",
        "description": "Polymorphic malware execution behavior detected."
    },

    1795: {
        "name": "Steganography Payload Delivery",
        "severity": "HIGH",
        "description": "Potential steganography-based payload delivery detected."
    },

    1796: {
        "name": "Encrypted Payload Staging",
        "severity": "HIGH",
        "description": "Encrypted malware payload staging activity detected."
    },

    1797: {
        "name": "Covert Channel Communication",
        "severity": "CRITICAL",
        "description": "Potential covert communication channel detected."
    },

    1798: {
        "name": "Malware Sleep Obfuscation",
        "severity": "HIGH",
        "description": "Malware sleep obfuscation technique detected."
    },

    1799: {
        "name": "Process Reimaging Attack",
        "severity": "CRITICAL",
        "description": "Process reimaging or stealth replacement detected."
    },

    1800: {
        "name": "Adaptive Command And Control",
        "severity": "CRITICAL",
        "description": "Adaptive command-and-control communication detected."
    },

        1801: {
        "name": "EDR Blindness Attempt",
        "severity": "CRITICAL",
        "description": "Attempt to blind or disable endpoint detection telemetry detected."
    },

    1802: {
        "name": "Security Event Suppression",
        "severity": "CRITICAL",
        "description": "Suppression of security monitoring events detected."
    },

    1803: {
        "name": "Tampered Security Configuration",
        "severity": "CRITICAL",
        "description": "Critical security configuration tampering detected."
    },

    1804: {
        "name": "Malicious Driver Communication",
        "severity": "CRITICAL",
        "description": "Communication with potentially malicious kernel driver detected."
    },

    1805: {
        "name": "Userland Hook Removal",
        "severity": "HIGH",
        "description": "Userland security hook removal detected."
    },

    1806: {
        "name": "Direct LSASS Memory Read",
        "severity": "CRITICAL",
        "description": "Direct memory access to LSASS process detected."
    },

    1807: {
        "name": "Credential Material In Memory",
        "severity": "CRITICAL",
        "description": "Credential material exposed in process memory detected."
    },

    1808: {
        "name": "Suspicious SAMR Enumeration",
        "severity": "HIGH",
        "description": "Unexpected Security Account Manager enumeration detected."
    },

    1809: {
        "name": "Admin Share Lateral Tool Transfer",
        "severity": "HIGH",
        "description": "Potential lateral movement tool transfer over admin shares detected."
    },

    1810: {
        "name": "Executable Copied To Remote Host",
        "severity": "HIGH",
        "description": "Executable copied to remote endpoint detected."
    },

    1811: {
        "name": "Credential Replay Over SMB",
        "severity": "CRITICAL",
        "description": "Credential replay attack over SMB detected."
    },

    1812: {
        "name": "Unauthorized Remote Registry Modification",
        "severity": "HIGH",
        "description": "Remote registry modification activity detected."
    },

    1813: {
        "name": "PsExec Service Artifact",
        "severity": "HIGH",
        "description": "PsExec service artifact detected on endpoint."
    },

    1814: {
        "name": "Suspicious Service Binary Path",
        "severity": "HIGH",
        "description": "Service configured with suspicious executable path."
    },

    1815: {
        "name": "Hidden Service Installation",
        "severity": "CRITICAL",
        "description": "Hidden or stealth service installation detected."
    },

    1816: {
        "name": "Windows Defender Exclusion Added",
        "severity": "CRITICAL",
        "description": "New Microsoft Defender exclusion added."
    },

    1817: {
        "name": "AMSI Provider Tampering",
        "severity": "CRITICAL",
        "description": "AMSI provider tampering activity detected."
    },

    1818: {
        "name": "Suspicious CLR Loading",
        "severity": "HIGH",
        "description": ".NET CLR loaded into unexpected process."
    },

    1819: {
        "name": "Inline Assembly Execution",
        "severity": "HIGH",
        "description": "Inline assembly execution behavior detected."
    },

    1820: {
        "name": "Malicious Reflective Assembly Load",
        "severity": "CRITICAL",
        "description": "Reflective .NET assembly loading detected."
    },

    1821: {
        "name": "Named Pipe Impersonation",
        "severity": "HIGH",
        "description": "Named pipe impersonation technique detected."
    },

    1822: {
        "name": "Token Impersonation Attack",
        "severity": "CRITICAL",
        "description": "Privilege escalation through token impersonation detected."
    },

    1823: {
        "name": "Suspicious RPC Endpoint Registration",
        "severity": "HIGH",
        "description": "Unexpected RPC endpoint registration detected."
    },

    1824: {
        "name": "Kerberos PAC Forgery",
        "severity": "CRITICAL",
        "description": "Kerberos PAC forgery attack detected."
    },

    1825: {
        "name": "Abnormal TGT Lifetime",
        "severity": "HIGH",
        "description": "Kerberos TGT lifetime anomaly detected."
    },

    1826: {
        "name": "Forged Service Ticket Usage",
        "severity": "CRITICAL",
        "description": "Forged Kerberos service ticket detected."
    },

    1827: {
        "name": "Delegation Ticket Abuse",
        "severity": "CRITICAL",
        "description": "Kerberos delegation ticket abuse detected."
    },

    1828: {
        "name": "Rubeus Tool Activity",
        "severity": "CRITICAL",
        "description": "Potential Rubeus Kerberos abuse activity detected."
    },

    1829: {
        "name": "BloodHound Enumeration",
        "severity": "HIGH",
        "description": "BloodHound-style Active Directory enumeration detected."
    },

    1830: {
        "name": "SharpHound Collector Execution",
        "severity": "HIGH",
        "description": "SharpHound Active Directory collector execution detected."
    },

    1831: {
        "name": "Suspicious LDAP Collection",
        "severity": "HIGH",
        "description": "Large-scale LDAP data collection detected."
    },

    1832: {
        "name": "Mass Group Membership Enumeration",
        "severity": "MEDIUM",
        "description": "Large-scale security group enumeration detected."
    },

    1833: {
        "name": "Domain Trust Mapping",
        "severity": "MEDIUM",
        "description": "Domain trust mapping activity detected."
    },

    1834: {
        "name": "Forest Trust Enumeration",
        "severity": "MEDIUM",
        "description": "Forest trust relationship enumeration detected."
    },

    1835: {
        "name": "Excessive Kerberos Requests",
        "severity": "HIGH",
        "description": "Unusual Kerberos request volume detected."
    },

    1836: {
        "name": "Unusual Ticket Encryption Type",
        "severity": "MEDIUM",
        "description": "Unexpected Kerberos encryption type detected."
    },

    1837: {
        "name": "Anonymous LDAP Bind",
        "severity": "HIGH",
        "description": "Anonymous LDAP bind request detected."
    },

    1838: {
        "name": "Machine Account Abuse",
        "severity": "HIGH",
        "description": "Potential machine account abuse detected."
    },

    1839: {
        "name": "Computer Object Takeover",
        "severity": "CRITICAL",
        "description": "Potential computer account takeover detected."
    },

    1840: {
        "name": "Suspicious GMSA Usage",
        "severity": "HIGH",
        "description": "Unexpected Group Managed Service Account usage detected."
    },

    1841: {
        "name": "Protected Users Group Modification",
        "severity": "CRITICAL",
        "description": "Protected Users group membership modified."
    },

    1842: {
        "name": "Authentication Policy Modification",
        "severity": "HIGH",
        "description": "Authentication policy modification detected."
    },

    1843: {
        "name": "Authentication Silos Tampering",
        "severity": "HIGH",
        "description": "Authentication policy silo modification detected."
    },

    1844: {
        "name": "Credential Roaming Abuse",
        "severity": "HIGH",
        "description": "Credential roaming abuse activity detected."
    },

    1845: {
        "name": "Smart Card Required Flag Removed",
        "severity": "HIGH",
        "description": "Smart card enforcement removed from account."
    },

    1846: {
        "name": "NTLM Usage In Restricted Environment",
        "severity": "HIGH",
        "description": "NTLM authentication used in restricted environment."
    },

    1847: {
        "name": "LSA Authentication Package Injection",
        "severity": "CRITICAL",
        "description": "LSA authentication package injection detected."
    },

    1848: {
        "name": "Suspicious SSP Registration",
        "severity": "CRITICAL",
        "description": "Unexpected Security Support Provider registration detected."
    },

    1849: {
        "name": "Credential Provider Tampering",
        "severity": "HIGH",
        "description": "Credential provider modification detected."
    },

    1850: {
        "name": "Windows Hello Configuration Tampering",
        "severity": "HIGH",
        "description": "Windows Hello security configuration modified."
    },

    1851: {
        "name": "Browser Password Export",
        "severity": "CRITICAL",
        "description": "Browser password export activity detected."
    },

    1852: {
        "name": "Suspicious Autofill Extraction",
        "severity": "HIGH",
        "description": "Browser autofill data extraction detected."
    },

    1853: {
        "name": "Cookie Database Access",
        "severity": "HIGH",
        "description": "Direct access to browser cookie database detected."
    },

    1854: {
        "name": "Session Token Replay",
        "severity": "CRITICAL",
        "description": "Stolen session token replay activity detected."
    },

    1855: {
        "name": "Clipboard Credential Capture",
        "severity": "HIGH",
        "description": "Credential capture through clipboard monitoring detected."
    },

    1856: {
        "name": "Screen Recording Malware",
        "severity": "HIGH",
        "description": "Unauthorized screen recording activity detected."
    },

    1857: {
        "name": "Unauthorized Webcam Access",
        "severity": "HIGH",
        "description": "Unexpected webcam access detected."
    },

    1858: {
        "name": "Microphone Surveillance Activity",
        "severity": "HIGH",
        "description": "Unauthorized microphone access detected."
    },

    1859: {
        "name": "Keylogging Hook Installation",
        "severity": "CRITICAL",
        "description": "Keyboard hook installation associated with keylogging detected."
    },

    1860: {
        "name": "Raw Input Capture",
        "severity": "HIGH",
        "description": "Raw keyboard input capture activity detected."
    },

    1861: {
        "name": "User Session Hijacking",
        "severity": "CRITICAL",
        "description": "Interactive user session hijacking detected."
    },

    1862: {
        "name": "Interactive Shell Spawned By Office",
        "severity": "CRITICAL",
        "description": "Office application spawned interactive shell."
    },

    1863: {
        "name": "Office Spawned LOLBin",
        "severity": "CRITICAL",
        "description": "Office application spawned living-off-the-land binary."
    },

    1864: {
        "name": "Unexpected Child Process From Browser",
        "severity": "HIGH",
        "description": "Web browser spawned unexpected child process."
    },

    1865: {
        "name": "Browser Spawned PowerShell",
        "severity": "CRITICAL",
        "description": "Browser process spawned PowerShell."
    },

    1866: {
        "name": "Remote Payload Via Clipboard",
        "severity": "HIGH",
        "description": "Payload delivery through clipboard detected."
    },

    1867: {
        "name": "Living-Off-The-Land Downloader",
        "severity": "HIGH",
        "description": "LOLBin-based payload downloader detected."
    },

    1868: {
        "name": "BITS Job Persistence",
        "severity": "HIGH",
        "description": "Persistence established through BITS job creation."
    },

    1869: {
        "name": "BITS Data Exfiltration",
        "severity": "HIGH",
        "description": "Data exfiltration through BITS transfer detected."
    },

    1870: {
        "name": "Suspicious Certutil Download",
        "severity": "HIGH",
        "description": "Payload download using certutil detected."
    },

    1871: {
        "name": "MSHTA Remote Execution",
        "severity": "CRITICAL",
        "description": "Remote payload execution through mshta detected."
    },

    1872: {
        "name": "Rundll32 JavaScript Execution",
        "severity": "CRITICAL",
        "description": "JavaScript execution through rundll32 detected."
    },

    1873: {
        "name": "Regsvr32 Scriptlet Execution",
        "severity": "CRITICAL",
        "description": "Remote scriptlet execution through regsvr32 detected."
    },

    1874: {
        "name": "InstallUtil Malware Proxy",
        "severity": "HIGH",
        "description": "InstallUtil used as malware execution proxy."
    },

    1875: {
        "name": "WMIC Remote Process Creation",
        "severity": "HIGH",
        "description": "Remote process creation through WMIC detected."
    },

    1876: {
        "name": "WinRS Remote Command",
        "severity": "HIGH",
        "description": "Remote command execution through WinRS detected."
    },

    1877: {
        "name": "PowerShell Web Request",
        "severity": "HIGH",
        "description": "PowerShell outbound web request detected."
    },

    1878: {
        "name": "Encoded Command Line Execution",
        "severity": "HIGH",
        "description": "Encoded command-line execution detected."
    },

    1879: {
        "name": "Compressed Payload Execution",
        "severity": "HIGH",
        "description": "Compressed or packed payload execution detected."
    },

    1880: {
        "name": "Obfuscated Script Content",
        "severity": "HIGH",
        "description": "Script obfuscation behavior detected."
    },

    1881: {
        "name": "Memory-Only Payload",
        "severity": "CRITICAL",
        "description": "Payload executed entirely from memory detected."
    },

    1882: {
        "name": "Shellcode Injection Attempt",
        "severity": "CRITICAL",
        "description": "Shellcode injection activity detected."
    },

    1883: {
        "name": "Remote APC Queue Injection",
        "severity": "CRITICAL",
        "description": "Remote APC queue code injection detected."
    },

    1884: {
        "name": "Thread Stack Spoofing",
        "severity": "HIGH",
        "description": "Thread stack spoofing technique detected."
    },

    1885: {
        "name": "Indirect Syscall Execution",
        "severity": "HIGH",
        "description": "Indirect syscall execution evasion detected."
    },

    1886: {
        "name": "Call Stack Manipulation",
        "severity": "HIGH",
        "description": "Call stack manipulation behavior detected."
    },

    1887: {
        "name": "Heap Encryption Activity",
        "severity": "HIGH",
        "description": "Heap encryption or memory concealment detected."
    },

    1888: {
        "name": "Runtime PE Decryption",
        "severity": "CRITICAL",
        "description": "Runtime executable decryption detected."
    },

    1889: {
        "name": "Malicious Sleep Masking",
        "severity": "HIGH",
        "description": "Malware sleep masking technique detected."
    },

    1890: {
        "name": "Process Ghosting",
        "severity": "CRITICAL",
        "description": "Process ghosting evasion technique detected."
    },

    1891: {
        "name": "Phantom DLL Hijacking",
        "severity": "HIGH",
        "description": "Phantom DLL hijacking behavior detected."
    },

    1892: {
        "name": "Section Mapping Injection",
        "severity": "CRITICAL",
        "description": "Section mapping process injection detected."
    },

    1893: {
        "name": "Kernel Callback Injection",
        "severity": "CRITICAL",
        "description": "Kernel callback injection technique detected."
    },

    1894: {
        "name": "Userland Rootkit Activity",
        "severity": "CRITICAL",
        "description": "Userland rootkit behavior detected."
    },

    1895: {
        "name": "DNS Over HTTPS Abuse",
        "severity": "HIGH",
        "description": "Potential malicious DNS over HTTPS activity detected."
    },

    1896: {
        "name": "Encrypted C2 Over WebSocket",
        "severity": "CRITICAL",
        "description": "Encrypted WebSocket command-and-control traffic detected."
    },

    1897: {
        "name": "Domain Fronting Activity",
        "severity": "HIGH",
        "description": "Potential domain fronting technique detected."
    },

    1898: {
        "name": "TLS Fingerprint Evasion",
        "severity": "HIGH",
        "description": "TLS fingerprint randomization or evasion detected."
    },

    1899: {
        "name": "Covert DNS Command Channel",
        "severity": "CRITICAL",
        "description": "DNS-based covert command channel detected."
    },

    1900: {
        "name": "Multi-Hop Proxy Evasion",
        "severity": "HIGH",
        "description": "Multi-hop proxy or relay evasion activity detected."
    },

        1901: {
        "name": "User Logged Off",
        "severity": "LOW",
        "description": "User logoff activity detected."
    },

    1902: {
        "name": "Screen Saver Activated",
        "severity": "LOW",
        "description": "Screen saver activation detected."
    },

    1903: {
        "name": "Screen Unlock Event",
        "severity": "LOW",
        "description": "User workstation unlock detected."
    },

    1904: {
        "name": "USB Device Removed",
        "severity": "LOW",
        "description": "USB storage device removal detected."
    },

    1905: {
        "name": "Printer Queue Access",
        "severity": "LOW",
        "description": "Printer queue access activity detected."
    },

    1906: {
        "name": "Bluetooth Device Discovery",
        "severity": "LOW",
        "description": "Bluetooth device discovery operation detected."
    },

    1907: {
        "name": "Wireless Network Scan",
        "severity": "LOW",
        "description": "Wireless network scanning activity detected."
    },

    1908: {
        "name": "Successful VPN Connection",
        "severity": "LOW",
        "description": "Successful VPN connection established."
    },

    1909: {
        "name": "VPN Disconnection",
        "severity": "LOW",
        "description": "VPN session disconnected."
    },

    1910: {
        "name": "DNS Cache Flush",
        "severity": "LOW",
        "description": "DNS resolver cache flush detected."
    },

    1911: {
        "name": "DHCP Lease Renewal",
        "severity": "LOW",
        "description": "DHCP lease renewal activity detected."
    },

    1912: {
        "name": "NTP Synchronization",
        "severity": "LOW",
        "description": "System time synchronization completed."
    },

    1913: {
        "name": "Successful SMB Authentication",
        "severity": "LOW",
        "description": "Successful SMB authentication detected."
    },

    1914: {
        "name": "Network Share Access",
        "severity": "LOW",
        "description": "Network share access activity detected."
    },

    1915: {
        "name": "Remote Desktop Connection Closed",
        "severity": "LOW",
        "description": "Remote Desktop session closed."
    },

    1916: {
        "name": "System Reboot Completed",
        "severity": "LOW",
        "description": "System reboot completed successfully."
    },

    1917: {
        "name": "Windows Update Installed",
        "severity": "LOW",
        "description": "Windows update installation completed."
    },

    1918: {
        "name": "Antivirus Signature Updated",
        "severity": "LOW",
        "description": "Antivirus signature database updated."
    },

    1919: {
        "name": "Firewall Service Started",
        "severity": "LOW",
        "description": "Windows Firewall service started."
    },

    1920: {
        "name": "Defender Quick Scan Completed",
        "severity": "LOW",
        "description": "Microsoft Defender quick scan completed."
    },

    1921: {
        "name": "Scheduled Backup Completed",
        "severity": "LOW",
        "description": "Scheduled backup operation completed."
    },

    1922: {
        "name": "User Profile Loaded",
        "severity": "LOW",
        "description": "User profile successfully loaded."
    },

    1923: {
        "name": "User Profile Unloaded",
        "severity": "LOW",
        "description": "User profile unloaded successfully."
    },

    1924: {
        "name": "Application Installed",
        "severity": "LOW",
        "description": "Application installation detected."
    },

    1925: {
        "name": "Application Uninstalled",
        "severity": "LOW",
        "description": "Application uninstallation detected."
    },

    1926: {
        "name": "Browser Cache Cleared",
        "severity": "LOW",
        "description": "Browser cache clearing activity detected."
    },

    1927: {
        "name": "New Browser Tab Opened",
        "severity": "LOW",
        "description": "Browser tab creation event detected."
    },

    1928: {
        "name": "Clipboard Content Changed",
        "severity": "LOW",
        "description": "Clipboard content modification detected."
    },

    1929: {
        "name": "Audio Device Connected",
        "severity": "LOW",
        "description": "Audio device connection detected."
    },

    1930: {
        "name": "Audio Device Disconnected",
        "severity": "LOW",
        "description": "Audio device disconnection detected."
    },

    1931: {
        "name": "Battery Power Connected",
        "severity": "LOW",
        "description": "External power connection detected."
    },

    1932: {
        "name": "Battery Running Low",
        "severity": "LOW",
        "description": "Low battery status detected."
    },

    1933: {
        "name": "Sleep Mode Activated",
        "severity": "LOW",
        "description": "System entered sleep mode."
    },

    1934: {
        "name": "System Wake Event",
        "severity": "LOW",
        "description": "System resumed from sleep state."
    },

    1935: {
        "name": "Monitor Resolution Changed",
        "severity": "LOW",
        "description": "Display resolution configuration changed."
    },

    1936: {
        "name": "Wallpaper Changed",
        "severity": "LOW",
        "description": "Desktop wallpaper modification detected."
    },

    1937: {
        "name": "Theme Configuration Changed",
        "severity": "LOW",
        "description": "Desktop theme configuration changed."
    },

    1938: {
        "name": "Time Zone Changed",
        "severity": "LOW",
        "description": "System time zone modification detected."
    },

    1939: {
        "name": "Keyboard Layout Changed",
        "severity": "LOW",
        "description": "Keyboard layout configuration changed."
    },

    1940: {
        "name": "Language Pack Installed",
        "severity": "LOW",
        "description": "Language pack installation detected."
    },

    1941: {
        "name": "Default Browser Changed",
        "severity": "LOW",
        "description": "Default browser configuration modified."
    },

    1942: {
        "name": "Default Printer Changed",
        "severity": "LOW",
        "description": "Default printer configuration modified."
    },

    1943: {
        "name": "New WiFi Profile Added",
        "severity": "LOW",
        "description": "Wireless network profile created."
    },

    1944: {
        "name": "WiFi Profile Removed",
        "severity": "LOW",
        "description": "Wireless network profile removed."
    },

    1945: {
        "name": "Successful Web Authentication",
        "severity": "LOW",
        "description": "Successful web portal authentication detected."
    },

    1946: {
        "name": "Successful MFA Challenge",
        "severity": "LOW",
        "description": "Multi-factor authentication challenge completed successfully."
    },

    1947: {
        "name": "Cloud Sync Completed",
        "severity": "LOW",
        "description": "Cloud synchronization completed successfully."
    },

    1948: {
        "name": "File Download Completed",
        "severity": "LOW",
        "description": "File download operation completed."
    },

    1949: {
        "name": "File Upload Completed",
        "severity": "LOW",
        "description": "File upload operation completed."
    },

    1950: {
        "name": "Archive Extraction Completed",
        "severity": "LOW",
        "description": "Archive extraction completed successfully."
    },

    1951: {
        "name": "Compression Task Completed",
        "severity": "LOW",
        "description": "File compression operation completed."
    },

    1952: {
        "name": "New Scheduled Task Registered",
        "severity": "LOW",
        "description": "Scheduled task registration detected."
    },

    1953: {
        "name": "Task Scheduler Triggered",
        "severity": "LOW",
        "description": "Scheduled task execution triggered."
    },

    1954: {
        "name": "Remote Assistance Session Closed",
        "severity": "LOW",
        "description": "Remote Assistance session ended."
    },

    1955: {
        "name": "Successful Kerberos Authentication",
        "severity": "LOW",
        "description": "Successful Kerberos authentication detected."
    },

    1956: {
        "name": "DNS Resolution Successful",
        "severity": "LOW",
        "description": "DNS hostname resolution completed."
    },

    1957: {
        "name": "Printer Driver Installed",
        "severity": "LOW",
        "description": "Printer driver installation detected."
    },

    1958: {
        "name": "Print Job Completed",
        "severity": "LOW",
        "description": "Print job completed successfully."
    },

    1959: {
        "name": "External Monitor Connected",
        "severity": "LOW",
        "description": "External display connection detected."
    },

    1960: {
        "name": "External Monitor Disconnected",
        "severity": "LOW",
        "description": "External display disconnection detected."
    },

    1961: {
        "name": "Successful Local Login",
        "severity": "LOW",
        "description": "Successful local user authentication detected."
    },

    1962: {
        "name": "Successful Domain Login",
        "severity": "LOW",
        "description": "Successful domain authentication detected."
    },

    1963: {
        "name": "Successful Cached Credential Login",
        "severity": "LOW",
        "description": "Cached credential authentication succeeded."
    },

    1964: {
        "name": "Successful Smart Card Login",
        "severity": "LOW",
        "description": "Smart card authentication completed successfully."
    },

    1965: {
        "name": "User Account Password Changed",
        "severity": "LOW",
        "description": "User account password change completed."
    },

    1966: {
        "name": "Successful Password Reset",
        "severity": "LOW",
        "description": "Password reset operation completed successfully."
    },

    1967: {
        "name": "New Local Group Created",
        "severity": "LOW",
        "description": "Local group creation detected."
    },

    1968: {
        "name": "User Added To Standard Group",
        "severity": "LOW",
        "description": "User added to non-privileged security group."
    },

    1969: {
        "name": "User Removed From Standard Group",
        "severity": "LOW",
        "description": "User removed from non-privileged security group."
    },

    1970: {
        "name": "System Environment Variable Changed",
        "severity": "LOW",
        "description": "Environment variable modification detected."
    },

    1971: {
        "name": "Recycle Bin Activity",
        "severity": "LOW",
        "description": "Recycle Bin usage activity detected."
    },

    1972: {
        "name": "Temporary File Cleanup",
        "severity": "LOW",
        "description": "Temporary file cleanup operation detected."
    },

    1973: {
        "name": "Disk Cleanup Utility Executed",
        "severity": "LOW",
        "description": "Disk cleanup utility execution detected."
    },

    1974: {
        "name": "Defragmentation Completed",
        "severity": "LOW",
        "description": "Disk defragmentation completed successfully."
    },

    1975: {
        "name": "Volume Mounted",
        "severity": "LOW",
        "description": "Storage volume mounted successfully."
    },

    1976: {
        "name": "Volume Unmounted",
        "severity": "LOW",
        "description": "Storage volume unmounted successfully."
    },

    1977: {
        "name": "Successful Driver Installation",
        "severity": "LOW",
        "description": "Driver installation completed successfully."
    },

    1978: {
        "name": "Bluetooth Pairing Successful",
        "severity": "LOW",
        "description": "Bluetooth pairing completed successfully."
    },

    1979: {
        "name": "Successful DHCP Assignment",
        "severity": "LOW",
        "description": "DHCP IP address assignment completed."
    },

    1980: {
        "name": "File Rename Operation",
        "severity": "LOW",
        "description": "File rename activity detected."
    },

    1981: {
        "name": "Directory Creation",
        "severity": "LOW",
        "description": "New directory creation detected."
    },

    1982: {
        "name": "Directory Removal",
        "severity": "LOW",
        "description": "Directory removal activity detected."
    },

    1983: {
        "name": "Successful Software Update",
        "severity": "LOW",
        "description": "Software update completed successfully."
    },

    1984: {
        "name": "Browser Bookmark Added",
        "severity": "LOW",
        "description": "Browser bookmark creation detected."
    },

    1985: {
        "name": "System Notification Generated",
        "severity": "LOW",
        "description": "Standard system notification event detected."
    },

    1986: {
        "name": "Desktop Shortcut Created",
        "severity": "LOW",
        "description": "Desktop shortcut creation detected."
    },

    1987: {
        "name": "Desktop Shortcut Removed",
        "severity": "LOW",
        "description": "Desktop shortcut removal detected."
    },

    1988: {
        "name": "Clipboard Copy Operation",
        "severity": "LOW",
        "description": "Clipboard copy operation detected."
    },

    1989: {
        "name": "Clipboard Paste Operation",
        "severity": "LOW",
        "description": "Clipboard paste operation detected."
    },

    1990: {
        "name": "Successful Proxy Authentication",
        "severity": "LOW",
        "description": "Proxy authentication completed successfully."
    },

    1991: {
        "name": "Successful Email Synchronization",
        "severity": "LOW",
        "description": "Email synchronization completed successfully."
    },

    1992: {
        "name": "Cloud Drive Mounted",
        "severity": "LOW",
        "description": "Cloud storage drive mounted successfully."
    },

    1993: {
        "name": "Cloud Drive Unmounted",
        "severity": "LOW",
        "description": "Cloud storage drive unmounted successfully."
    },

    1994: {
        "name": "System Restore Point Created",
        "severity": "LOW",
        "description": "System restore point creation detected."
    },

    1995: {
        "name": "Application Configuration Saved",
        "severity": "LOW",
        "description": "Application configuration save operation detected."
    },

    1996: {
        "name": "Remote Session Connected",
        "severity": "LOW",
        "description": "Remote session connection established."
    },

    1997: {
        "name": "Remote Session Disconnected",
        "severity": "LOW",
        "description": "Remote session disconnected."
    },

    1998: {
        "name": "System Health Check Completed",
        "severity": "LOW",
        "description": "Routine system health check completed."
    },

    1999: {
        "name": "Successful Configuration Sync",
        "severity": "LOW",
        "description": "Configuration synchronization completed successfully."
    },

    2000: {
        "name": "Normal Application Exit",
        "severity": "LOW",
        "description": "Application terminated normally without errors."
    },

    4735: {
        "name": "Security Group Modified",
        "severity": "MEDIUM",
        "description": "A security-enabled local group was modified."
    },
    4741: {
        "name": "Computer Account Created",
        "severity": "MEDIUM",
        "description": "A new computer account was created."
    },
    4742: {
        "name": "Computer Account Changed",
        "severity": "MEDIUM",
        "description": "A computer account was modified."
    },
    4756: {
        "name": "Universal Group Member Added",
        "severity": "HIGH",
        "description": "A member was added to a security-enabled universal group."
    },
    7: {
        "name": "Sysmon Image Loaded",
        "severity": "MEDIUM",
        "description": "A module/image was loaded by a process (Sysmon Event ID 7)."
    },
    13: {
        "name": "Sysmon Registry Value Set",
        "severity": "MEDIUM",
        "description": "Registry value was set (Sysmon Event ID 13)."
    },
    3: {
        "name": "Sysmon Network Connection",
        "severity": "LOW",
        "description": "Network connection initiated (Sysmon Event ID 3)."
    },
    11: {
        "name": "Sysmon File Created",
        "severity": "LOW",
        "description": "File was created (Sysmon Event ID 11)."
    },
    4690: {
        "name": "Process Handle Duplicated",
        "severity": "MEDIUM",
        "description": "Process handle duplication detected. Often used in credential dumping."
    },
    4657: {
        "name": "Registry Value Modified",
        "severity": "MEDIUM",
        "description": "Registry value was modified."
    },
    5158: {
        "name": "Bind Request",
        "severity": "MEDIUM",
        "description": "Windows Filtering Platform permitted a bind to a local port."
    },
    5159: {
        "name": "Bind Request Blocked",
        "severity": "HIGH",
        "description": "Windows Filtering Platform blocked a bind to a local port."
    },
    4673: {
        "name": "Sensitive Privilege Use",
        "severity": "MEDIUM",
        "description": "A privileged service was called."
    },
    4674: {
        "name": "Operation Attempted On Privileged Object",
        "severity": "MEDIUM",
        "description": "An operation was attempted on a privileged object."
    },
    6416: {
        "name": "External Device Enumeration",
        "severity": "MEDIUM",
        "description": "A new external device was enumerated."
    },
}