# PHP2Shell — CVE-2026-109618 & CVE-2026-109619

## Overview

PHP2Shell refers to two critical vulnerabilities that may allow unauthenticated Remote Code Execution (RCE) on affected PHP systems.

- **CVE-2026-109618**
- **CVE-2026-109619**
- **Severity:** Critical
- **CVSS:** 9.2
- **Public disclosure:** 21 October 2026

Successful exploitation may allow an attacker to execute arbitrary code on a vulnerable server.

## Affected and Fixed Versions

| PHP Branch | Affected Versions | Fixed Version |
|---|---|---|
| PHP 8.5 | Before 8.5.12 | 8.5.12 |
| PHP 8.4 | Before 8.4.27 | 8.4.27 |
| PHP 8.3 | Before 8.3.36 | 8.3.36 |
| PHP 8.2 | Before 8.2.35 | 8.2.35 |

For older PHP branches, consult official vendor advisories for affected releases and available backported fixes.

## Indicators of Compromise (IOCs)

IP addresses reported in connection with observed PHP2Shell activity are maintained separately for easier updates.

**[View PHP2Shell IOCs](iocs/php2shell-ips.txt)**

Some addresses may belong to shared anonymisation infrastructure. Treat IOC matches as investigation leads, not definitive proof of compromise.

## Splunk Detection Rules

The following SPL rules provide starting points for detecting suspicious activity potentially associated with PHP2Shell. Adapt index names and field mappings to your environment.

### 1. Suspicious Multipart POST Requests

**MITRE ATT&CK:** [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

Detects POST requests containing `PHP_SESSION_UPLOAD_PROGRESS` in multipart form submissions.

```spl
index=web_logs "PHP_SESSION_UPLOAD_PROGRESS"
| eval http_method=upper(coalesce(method, http_method, request_method))
| eval content_type=lower(coalesce(content_type, http_content_type, ""))
| where http_method="POST"
    AND like(content_type, "%multipart/form-data%")
| table _time src_ip dest_ip host http_method uri status content_type
| sort - _time
```

**Telemetry requirement:** Web, WAF or reverse-proxy logs must capture the relevant request-body content or form field. Standard access logs may not contain this information.

### 2. Unexpected Shell Execution by PHP Workers

**MITRE ATT&CK:** [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

Detects PHP or web-server processes spawning unexpected shells and command-line utilities.

```spl
index=endpoint_logs
| eval parent=lower(coalesce(
    parent_process_name, ParentImage, parent_process, ""))
| eval child=lower(coalesce(
    process_name, Image, process, ""))
| where match(parent,
    "(^|/|\\\\)(php|php-fpm|httpd|apache2|nginx)(\\.exe)?$")
| where match(child,
    "(^|/|\\\\)(sh|bash|dash|cmd|powershell|curl|wget|nc|socat)(\\.exe)?$")
| table _time host user parent child process_command_line
| sort - _time
```

**Telemetry requirement:** Endpoint process-creation events containing parent and child process details. Review legitimate administrative scripts and expected application behaviour to reduce false positives.

### 3. Suspicious Downloads, File Writes and Outbound Connections

Hunts for potential post-exploitation activity involving PHP or web-server processes.

```spl
index=endpoint_logs
| eval process=lower(coalesce(
    process_name, Image, process, ""))
| eval event_type=lower(coalesce(
    event_type, action, category, ""))
| eval details=lower(coalesce(
    file_path, destination, command_line, process_command_line, ""))
| where match(process,
    "(^|/|\\\\)(php|php-fpm|httpd|apache2|nginx)(\\.exe)?$")
| where match(event_type,
    "network|connect|file|write|create|download")
    OR match(details,
    "curl|wget|\\.php|\\.sh|/tmp/|/var/tmp/")
| table _time host user process event_type details
| sort - _time
```

**Telemetry requirement:** Endpoint file and network events must be available in the selected index. Validate event names and field mappings against your data source before deployment.

## MITRE ATT&CK Mapping

- [**T1190 — Exploit Public-Facing Application**](https://attack.mitre.org/techniques/T1190/): Exploitation of an internet-facing PHP application.
- [**T1059 — Command and Scripting Interpreter**](https://attack.mitre.org/techniques/T1059/): Shell or command execution following exploitation.
- [**T1505.003 — Web Shell**](https://attack.mitre.org/techniques/T1505/003/): Relevant if a web shell is deployed or used after exploitation.

T1505.003 is applicable only when web-shell activity is suspected or observed; it is not implied by every exploitation attempt.

## Detection Limitations

- Request indicators alone do not prove successful exploitation.
- SPL index names and field mappings must be adapted to the available telemetry.
- Validate each rule against your environment before production deployment.
- Correlate suspicious requests with process, file and network events to investigate potential compromise.

## References

- [Amazon Threat Intelligence — PHP2Shell exploitation before public disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)
- [PHP Security Announcements](https://www.php.net/)

---

*Community detection research. Validate vulnerability details, IOC data and detection logic against authoritative advisories before operational use.*
