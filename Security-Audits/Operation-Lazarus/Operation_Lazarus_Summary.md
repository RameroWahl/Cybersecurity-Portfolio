
# Operation Lazarus - Cybersecurity Portfolio Highlight

## Summary
Operation Lazarus was a simulated red team engagement focused on node-to-node exploitation, privilege escalation, persistence, and data exfiltration.

## Objectives
- Breach corporate network perimeter.
- Extract the Project Lazarus AI prototype.
- Demonstrate multi-layer persistence.
- Achieve privilege escalation to root.

## Techniques Used
- **Recon & Vulnerability Scan:** Nmap scan, Apache CVE-2021-41773 exploit.
- **Privilege Escalation:** Cron job abuse, `/tmp` poisoning.
- **Persistence:** Cron backdoor in `backup.sh`.
- **Data Exfiltration:** `scp` Lazarus AI model and MySQL DB dump.
- **Credential Access:** Reused weak passwords and SSH key harvesting.
- **Covering Tracks:** Log wiping and history clearing.

## Loot Summary
- **Lazarus AI Model**
- **Database dump (users, transactions, logs)**
- **SSH Keys and plaintext credentials**

## Takeaways
- Multi-stage attack paths are realistic and devastating.
- Cron jobs are often overlooked attack vectors.
- Default or reused passwords remain a critical weakness.

## Tags
Red Team | Cron Hijack | Data Exfiltration | Privilege Escalation | Cyber War Story | Portfolio Showcase
