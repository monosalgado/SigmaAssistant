# Knowledge base of Sysmon Events
# Source based on standard Sysmon documentation

SYSMON_EVENTS = [
    {
        "id": "1",
        "name": "Process Creation",
        "description": "The process creation event provides extended information about a newly created process. The full command line provides context on the process execution.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine"]
    },
    {
        "id": "2",
        "name": "A process changed a file creation time",
        "description": "The change file creation time event is registered when a file creation time is explicitly modified by a process. This event helps tracking the real creation time of a file.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"]
    },
    {
        "id": "3",
        "name": "Network Connection",
        "description": "The network connection event logs TCP/UDP connections on the machine.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName"]
    },
    {
        "id": "4",
        "name": "Sysmon Service State Changed",
        "description": "The service state change event reports the state of the Sysmon service (started or stopped).",
        "fields": ["UtcTime", "State", "Version", "SchemaVersion"]
    },
    {
        "id": "5",
        "name": "Process Terminated",
        "description": "The process terminate event reports when a process terminates. It provides the UtcTime, ProcessGuid and ProcessId of the process.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image"]
    },
    {
        "id": "6",
        "name": "Driver Loaded",
        "description": "The driver loaded events provides information about a driver being loaded on the system.",
        "fields": ["UtcTime", "ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus"]
    },
    {
        "id": "7",
        "name": "Image Loaded",
        "description": "The image loaded event logs when a module is loaded in a specific process.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "Hashes", "Signed", "Signature", "SignatureStatus"]
    },
    {
        "id": "8",
        "name": "CreateRemoteThread",
        "description": "The CreateRemoteThread event detects when a process creates a thread in another process. This technique is used by malware to inject code and hide in other processes.",
        "fields": ["UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "NewThreadId", "StartAddress", "StartModule", "StartFunction"]
    },
    {
        "id": "9",
        "name": "RawAccessRead",
        "description": "The RawAccessRead event detects when a process conducts reading operations from the drive using the \\\\.\\ denotation.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "Device"]
    },
    {
        "id": "10",
        "name": "ProcessAccess",
        "description": "The process accessed event reports when a process opens another process, an operation that’s often followed by information gathering or reading the address space of the target process.",
        "fields": ["UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceThreadId", "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "GrantedAccess", "CallTrace"]
    },
    {
        "id": "11",
        "name": "FileCreate",
        "description": "File create operations are logged when a file is created or overwritten.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime"]
    },
    {
        "id": "12",
        "name": "RegistryEvent (Object create and delete)",
        "description": "Registry key and value create and delete operations.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject"]
    },
    {
        "id": "13",
        "name": "RegistryEvent (Value Set)",
        "description": "Registry value set operations.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details"]
    },
    {
        "id": "14",
        "name": "RegistryEvent (Key and Value Rename)",
        "description": "Registry key and value rename operations.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "NewName"]
    },
    {
        "id": "15",
        "name": "FileCreateStreamHash",
        "description": "This event logs when a named file stream is created, and it generates events that log the hash of the contents of the file to which the stream is assigned.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime", "Hash"]
    },
    {
        "id": "17",
        "name": "PipeEvent (Pipe Created)",
        "description": "This event generates when a named pipe is created.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "PipeName", "Image"]
    },
    {
        "id": "18",
        "name": "PipeEvent (Pipe Connected)",
        "description": "This event logs when a named pipe connection is made between a client and a server.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "PipeName", "Image"]
    },
    {
        "id": "22",
        "name": "DNSEvent (DNS query)",
        "description": "This event generates when a process executes a DNS query, whether the result is successful or fails, cached or not.",
        "fields": ["UtcTime", "ProcessGuid", "ProcessId", "QueryName", "QueryStatus", "QueryResults", "Image"]
    }
]
