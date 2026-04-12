"""
Static mapping tables for Sigma → LEQL translation.
Used by the prompt builder to inject accurate field name context into the LLM.
"""

# Sigma field name → LEQL field name
SIGMA_TO_LEQL_FIELDS = {
    # Process fields
    "Image": "process_name",
    "NewProcessName": "process_name",
    "OriginalFileName": "process_name",
    "CommandLine": "process_cmdline",
    "ParentImage": "parent_process_name",
    "ParentCommandLine": "parent_process_cmdline",
    "ParentProcessId": "parent_process_id",
    "ProcessId": "process_id",
    "IntegrityLevel": "integrity_level",

    # File fields
    "TargetFilename": "file_path",
    "FileName": "file_path",
    "FilePath": "file_path",
    "CreationUtcTime": "file_creation_time",

    # Registry fields
    "TargetObject": "registry_key",
    "Details": "registry_value",
    "EventType": "event_type",

    # Network fields
    "DestinationIp": "destination_ip",
    "DestinationPort": "destination_port",
    "SourceIp": "source_ip",
    "SourcePort": "source_port",
    "Initiated": "network_initiated",
    "Protocol": "network_protocol",
    "DestinationHostname": "destination_host",
    "QueryName": "dns_query",
    "QueryResults": "dns_answer",

    # User / auth fields
    "User": "user",
    "SubjectUserName": "user",
    "TargetUserName": "target_user",
    "SubjectDomainName": "domain",
    "LogonType": "logon_type",

    # Module / driver fields
    "ImageLoaded": "module_path",
    "Signed": "module_signed",
    "SignatureStatus": "module_signature_status",

    # Pipe fields
    "PipeName": "pipe_name",

    # Service fields
    "ServiceName": "service_name",

    # Hash fields
    "Hashes": "sha256",
    "MD5": "md5",
    "SHA1": "sha1",
    "SHA256": "sha256",

    # Generic / Windows event fields
    "EventID": "event_code",
    "Channel": "channel",
    "Provider_Name": "provider",
    "Computer": "hostname",

    # Web / proxy fields
    "cs-uri-query": "url",
    "cs-method": "http_method",
    "c-ip": "source_ip",
    "sc-status": "http_status_code",
    "cs-host": "destination_host",
    "c-useragent": "user_agent",

    # Cloud fields (AWS)
    "eventName": "event_name",
    "eventSource": "event_source",
    "sourceIPAddress": "source_ip",
    "userIdentity.type": "user_type",
    "userIdentity.userName": "user",
    "requestParameters.bucketName": "bucket_name",
}


# (category, product, service) → LEQL log set name
# Use None for wildcard entries (e.g., product=None means any product)
SIGMA_TO_LEQL_LOGSOURCE = {
    # Windows Sysmon categories
    ("process_creation", "windows", "sysmon"): "endpoint",
    ("process_creation", "windows", None): "endpoint",
    ("process_creation", None, None): "endpoint",
    ("file_event", "windows", "sysmon"): "endpoint",
    ("file_event", "windows", None): "endpoint",
    ("file_change", "windows", "sysmon"): "endpoint",
    ("registry_event", "windows", "sysmon"): "endpoint",
    ("registry_add", "windows", "sysmon"): "endpoint",
    ("registry_set", "windows", "sysmon"): "endpoint",
    ("registry_delete", "windows", "sysmon"): "endpoint",
    ("registry_rename", "windows", "sysmon"): "endpoint",
    ("network_connection", "windows", "sysmon"): "network_traffic",
    ("network_connection", "windows", None): "network_traffic",
    ("dns_query", "windows", "sysmon"): "dns",
    ("dns_query", "windows", None): "dns",
    ("image_load", "windows", "sysmon"): "endpoint",
    ("pipe_created", "windows", "sysmon"): "endpoint",
    ("process_access", "windows", "sysmon"): "endpoint",
    ("driver_loaded", "windows", "sysmon"): "endpoint",
    ("create_remote_thread", "windows", "sysmon"): "endpoint",
    ("raw_access_thread", "windows", "sysmon"): "endpoint",
    # Windows event log services
    (None, "windows", "security"): "ingress_authentication",
    (None, "windows", "system"): "windows_events",
    (None, "windows", "application"): "windows_events",
    (None, "windows", "powershell"): "powershell",
    (None, "windows", "powershell-classic"): "powershell",
    (None, "windows", "bits-client"): "windows_events",
    (None, "windows", "taskscheduler"): "windows_events",
    ("ps_script", "windows", None): "powershell",
    ("ps_module", "windows", None): "powershell",
    # Web / proxy
    ("webserver", None, None): "web",
    ("proxy", None, None): "web",
    # Network
    ("firewall", None, None): "network_traffic",
    ("dns", None, None): "dns",
    # Cloud
    (None, "aws", "cloudtrail"): "aws_cloudtrail",
    (None, "azure", "activitylogs"): "azure_ad",
    (None, "gcp", "audit"): "gcp_audit",
    # Linux
    ("process_creation", "linux", None): "endpoint",
    (None, "linux", "auditd"): "endpoint",
}
