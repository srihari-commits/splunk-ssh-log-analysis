# splunk-ssh-log-analysis
SOC Analysis and Detection engineering using Splunk SPL

This project demonstrates end-to-end security operations center (SOC) log analysis using Splunk Enterprise to analyze Linux SSH authentication activity. The objective is to establish visibility into remote access events, detect brute-force authentication attacks, trace successful logins following multiple failures, and identify unauthenticated network probing.

Scope and Infrastructure

Platform: Splunk Enterprise
Log Source: Linux OpenSSH Authentication Logs (/var/log/auth.log / secure)
Target Index: ssh_logs
Query Language: Splunk Search Processing Language (SPL)

Technical Tasks and Detection Engineering
Task 1: Ingestion and Event Taxonomy Validation
Query :  
         index="ssh_logs" 
         | stats count by event_type

Task 2: Authentication Failure Analysis
Query :
        index="ssh_logs" event_type="failed_ssh_login" 
        | stats count by id.orig_h 
        | sort - count 

Task 3: SSH Brute-Force Attack Detection
Query : 
        index="ssh_logs" event_type="multiple_failed_login" 
        | stats count by id.orig_h, id.resp_h
        | sort - count

Task 4: Post-Exploitation Verification (Account Compromise Tracking)
Query : 
        index="ssh_logs" event_type="successful_ssh_login" id.origin_h="10.0.0.28"

         index="ssh_logs" event_type="successful_ssh_login" | stats count by id.origin_h,               id.resp_h
Task 5: Unauthenticated Network Connection Monitoring
Query :
        index="ssh_logs" event_type="connection_without_authentication" 
        | timechart count by id.origin_h


## Remediation and Risk Mitigation
1. **Network Perimeter Controls:** Automatically append IP addresses exceeding failure thresholds to perimeter firewall dynamic blocklists.
2. **Access Control Hardening:** Disable password-based SSH authentication (`PasswordAuthentication no`) in favor of public-key authentication.
3. **Automated Response Integration:** Deploy host-based prevention tools such as `fail2ban` or integrate Splunk SOAR playbooks for immediate threat containment.
