from sigma.collection import SigmaCollection
from sigma.backends.insight_idr import InsightIDRBackend

# Sample Sigma Rule
sigma_rule = """
title: Suspicious PowerShell Download
id: 5f1f759f-d9d3-4d6a-91ef-c1071c6a2d21
status: test
description: Detects suspicious PowerShell download
author: Read Team
date: 2021/08/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
        CommandLine|contains: 'DownloadString'
    condition: selection
"""

try:
    print("Loading Sigma rule...")
    collection = SigmaCollection.from_yaml(sigma_rule)
    
    print("Initializing InsightIDRBackend...")
    backend = InsightIDRBackend()
    
    print("Converting...")
    # InsightIDR backend might produce a list of queries
    queries = backend.convert(collection)
    
    print("\nGenerated LEQL Queries:")
    for q in queries:
        print(f"- {q}")
        
except Exception as e:
    print(f"Error: {e}")
