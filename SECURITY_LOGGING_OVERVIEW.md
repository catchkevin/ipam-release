# IPAM — Security and Logging Overview

**For compliance, security and cyber-security teams evaluating IPAM**

Version 0.1.0 · October 2026

---

## Contents

1. [Summary](#1-summary)
2. [Security by design: the principles](#2-security-by-design-the-principles)
3. [What IPAM records](#3-what-ipam-records)
4. [Five log files, one audience each](#4-five-log-files-one-audience-each)
5. [Every line: the field dictionary](#5-every-line-the-field-dictionary)
6. [Event IDs](#6-event-ids)
7. [Tamper evidence](#7-tamper-evidence)
8. [Retention, compression and long-term archiving](#8-retention-compression-and-long-term-archiving)
9. [The database audit log, and the database server's own logs](#9-the-database-audit-log-and-the-database-servers-own-logs)
10. [Logs around IPAM: the server, the container, the proxy](#10-logs-around-ipam-the-server-the-container-the-proxy)
11. [Bringing the logs into a SIEM](#11-bringing-the-logs-into-a-siem)
12. [Investigations: what a security team can answer](#12-investigations-what-a-security-team-can-answer)
13. [Protecting the logs, and what is never logged](#13-protecting-the-logs-and-what-is-never-logged)
14. [The rest of IPAM's security controls](#14-the-rest-of-ipams-security-controls)
15. [How the design supports common frameworks](#15-how-the-design-supports-common-frameworks)
16. [Known limits and the roadmap](#16-known-limits-and-the-roadmap)
17. [Questions security reviewers ask](#17-questions-security-reviewers-ask)

This document is also in IPAM itself: **Help & Reference → Security & Logging Overview**, with a Download button.

---

## 1. Summary

IPAM (IP Address Management) keeps an organization's network plan: its network blocks, subnets, sites, and the people
and teams responsible for them. That plan is sensitive. It's a map of the network that an attacker would value, so IPAM
treats every action on it as something a security team may one day need to reconstruct.

**In one paragraph:**
- Every sign-in, every change to the data, every look at sensitive information, every export and every change to a
  security setting is recorded twice: in IPAM's own database (searchable on the Audit log page) and in log files on the
  server.
- The log files are written for collection by the organization's SIEM (Splunk, Datadog, Elastic, Microsoft Sentinel,
  and others). There are five of them, so each audience can be given its own index and its own access.
- Each line has the same fixed fields, a permanent event ID, and a fingerprint chained to the line before it, so a
  changed, deleted or inserted line can be found.
- Passwords, cookies and connection strings are never written.

**At a glance**

| | |
|---|---|
| Where events are recorded | IPAM's database (the Audit log page) and five log files, plus the container console |
| Formats | JSON lines (default), CSV, key=value text. Any combination |
| Timestamps | UTC, ISO 8601 with milliseconds (`2026-10-17T14:07:03.427Z`) |
| Event catalog | About 130 events, each with a permanent ID, name and description, numbered by area |
| Who did it, from where | User, sign-in session, client IP, proxy chain, browser and operating system, the API call |
| Tamper evidence | SHA-256 hash chain on every line; a check on screen and a server command |
| Retention | Set per file, up to 3,650 days on disk; optional compression after N days; optional move to long-term storage instead of deletion; database audit log 30 to 3,650 days (default 366), archived before purging if chosen |
| Secrets | Never logged, checked by an automated test |
| Access to logs | Log Settings: Administrators only. Audit log page: the Audit Log Viewer role |
| Is logging working? | A **Logging status** bar on every page for Administrators: green "Successful", red "Down or Degraded" with the reason; each change of status is itself an event |

---

## 2. Security by design: the principles

IPAM's logging wasn't added at the end. It follows a few rules that every part of the app has to obey.

1. **Record the action at the moment it happens, in the same transaction.** A change to the data and its audit entry
   are saved together or not at all. A change can't be saved without its record, and a cancelled change leaves none.
2. **Every event has a permanent identity.** Each kind of event has a fixed ID that never changes meaning. Alerts,
   dashboards and saved searches built on an ID keep working across upgrades.
3. **One format, every field, every line.** Every log line has the same fields in the same order, whatever the event.
   A field with nothing to say is empty rather than missing, so a SIEM never has to guess.
4. **Separate by audience.** Five log files, so the people who need sign-in data, data-change history and security
   events can each be given exactly that, and nothing more.
5. **Show tampering.** Every line carries a fingerprint chained to the one before it.
6. **Never record secrets.** Passwords, hashes, cookies and connection strings stay out of every log, by design, and an
   automated test checks it.
7. **Fail safe, and say so.**
   - If a log file can't be written, IPAM keeps working, writes to the console and the startup log, and records a
     "log write failed" event once it can.
   - Administrators see a red **Logging status** bar on every page until it's fixed.
8. **Least privilege for the logs themselves.** Only Administrators change logging. Turning debug detail on is
   recorded, limited to 7 days, and switches itself off.
9. **Time is UTC, to the millisecond, everywhere.** Events from IPAM line up with events from firewalls, directories and
   other systems without conversion.

---

## 3. What IPAM records

IPAM records three kinds of thing.

**Changes to data, with the values before and after.**
- Network blocks: created, deleted, moved between workspaces, split, joined.
- Subnets: allocated; details changed (name, VLAN, site, gateway, notes, lists, cloud provider, type); sub blocks made
  or removed.
- Lists: sites, environments, divisions, products and block types added, changed, made active or inactive, deleted.
- Workspaces: created, changed, activated or deactivated, deleted.
- Changes made by imports, row by row.

**Who came in, and what they did.**
- Sign-in, failed sign-in (with the reason: unknown user, wrong password, disabled account), sign-out.
- Sessions that were no longer valid: a password reset or account disabled since; an expired or unreadable sign-in.
- Too many sign-in attempts from one address.
- Password changes and resets.
- Every screen opened, and one line for every request the browser made to the server.

**Everything a security team watches.**
- User accounts and groups: created, changed, enabled or disabled; group membership; which workspaces each person can
  see. Roles are built in and can't be changed, but who has them can, and every change is recorded.
- Access denied: someone tried an action their roles don't allow (the event names the role that was needed).
- Requests refused because they lacked IPAM's anti-forgery header (the signature of a cross-site request forgery).
- IP AllowList: entries added, changed, deleted or expired; enforcement turned on or off; each blocked attempt.
- Sensitive views: who opened the audit log, the users, the groups, the roles, the IP AllowList, the Settings, the
  Organization Settings, the Log Settings, the Database page, the backups.
- Searches, with what was searched for.
- Exports (what, which format, how many rows, which filters), import template downloads, and every import.
- Settings changes, the database being moved, log settings changed, debug logging turned on or off, log files deleted
  and audit entries purged by retention, log files checked for tampering.
- IPAM starting (with its version and settings), stopping, upgrading its database, or being stopped from starting by
  a safety check.

Operational messages, warnings and errors (with stack traces) are recorded for the people who run the server. While
an administrator has turned it on, extra debug detail is recorded too.

---

## 4. Five log files, one audience each

IPAM writes **five log files a day**. **Every kind of event always goes to the same one of the five.** A sign-in always
goes to the access file, a site change always to the payload file, an export always to the security file. So each file
can be sent to its own SIEM index, with its own access rules and its own retention, and nothing appears twice.

The **Event IDs** tab of Log Settings shows, for every event, which file it goes to. Every line in every file carries
the user, the sign-in session and the client IP, so one search can still follow a person across all of them.

| File | Holds | Typical readers |
|---|---|---|
| `ipam-access-YYYYMMDD` | Who came in, from where, and what they touched: sign-in, sign-out, failed sign-ins, rejected and expired sessions, rate limiting, password changes and resets, every screen opened, one line per API request | Security operations: sign-in monitoring, brute-force detection, "where was this account used from" |
| `ipam-payload-YYYYMMDD` | The data itself: every record created, changed (including made active or inactive) or removed, with old and new values | Data owners, change management, the network team. **Restrict:** it describes the network design |
| `ipam-security-YYYYMMDD` | Privileges and controls: users, groups and access; access denied; the security header; the IP AllowList; sensitive views and searches; exports, imports and templates; settings; the database; logging and its retention; start, stop and upgrade | The CISO's office and the SOC: privilege abuse, data leaving, controls being changed, logging being tampered with |
| `ipam-app-YYYYMMDD` | The app's own health: operational messages, warnings, errors with stack traces, backups | Operations and support |
| `ipam-debug-YYYYMMDD` | Only while debug logging is on: each request's query string and headers (cookies and credentials removed), response sizes, timings | Whoever is troubleshooting, for a limited time |

**Formats.** Each file can be written as JSON lines (the default, read by Splunk, Datadog, Elastic and Azure Monitor
with no set-up), CSV (with a header row), or key=value text (`field=value | field=value`), in any combination. All
formats hold the same fields in the same order and the same fingerprints.

**Rollover.**
- A new file starts each UTC day.
- A file that reaches 100 MB continues in `…-2`, `…-3`.
- There are no banner or header lines (CSV has its column row), so a SIEM never reads a decoration as an event.

**The console.** The same JSON line for every event in every file also goes to the container's console
(`docker logs`). That serves Docker logging drivers and Kubernetes collectors.

**The database.**
- **Kept in the database:** changes, sign-in events and security events. This is the history the Audit log page shows.
  Its entries reach the files within about a second of being saved, and only once saved, so a cancelled change (for
  example an import preview) never appears.
- **Files only:** screen views, per-request lines and debug detail, which are high in volume. This keeps the on-screen
  history focused.

**The Audit log page** (the Audit Log Viewer role):
- columns Date/Time, User, Client IP, Event ID, Event Name, Event Description and Event Details, and an optional
  Browser column;
- a search box above each column, and filters for user, kind of action, date range, status and client IP;
- an export of exactly what's shown;
- a **Tamper check** tab (section 7).

Opening the audit log is itself recorded.

---

## 5. Every line: the field dictionary

Every line has every field, in this order. An empty string means "not applicable to this event".

| # | Field | Meaning | Example |
|---|---|---|---|
| 1 | `timestamp` | UTC, ISO 8601, milliseconds | `2026-10-17T14:07:03.427Z` |
| 2 | `log_type` | The file it belongs to | `security` |
| 3 | `level` | `INFO`, `WARN`, `ERROR`, `DEBUG` | `WARN` |
| 4 | `event_id` | The permanent event ID | `1011` |
| 5 | `event_name` | The event's name | `Access denied` |
| 6 | `status` | `SUCCESS`, `FAILED`, `DENIED` (blank for operational messages) | `DENIED` |
| 7 | `message` | What happened, in a sentence | `Access denied: GET /api/users (needs users.view…)` |
| 8–9 | `app`, `app_version` | Product and version | `IPAM`, `0.1.0` |
| 10 | `environment` | Production, or Development on a developer's PC | `Production` |
| 11 | `host` | The server or container name | `ipam-01` |
| 12 | `instance_id` | A new ID each time IPAM starts | `4dff78e8…` |
| 13 | `db_provider` | SQLite, PostgreSQL or SQL Server | `PostgreSQL` |
| 14 | `request_id` | The API call's ID. Error messages on screen show it too, so a user's report can be traced to its lines | `0HNPC80E…:0000003C` |
| 15 | `session_id` | One ID per sign-in: every action of one sign-in shares it | `133d9876…` |
| 16–17 | `user`, `user_id` | Who (`system` for IPAM itself) | `jsmith`, `14` |
| 18 | `client_ip` | The address the request came from (the real client behind a trusted reverse proxy) | `198.51.100.23` |
| 19 | `proxy_chain` | `X-Forwarded-For` as received | `198.51.100.23, 10.0.0.5` |
| 20 | `user_agent` | The browser's full User-Agent | `Mozilla/5.0 …` |
| 21–22 | `browser`, `os` | Short forms | `Edge 141`, `Windows` |
| 23–24 | `http_method`, `path` | The call made, without the query string (screen views: `VIEW` and the screen) | `POST`, `/api/sites` |
| 25–26 | `http_status`, `duration_ms` | On request lines | `200`, `12` |
| 27 | `workspace` | The workspace the user was working in | `Production` |
| 28 | `action` | The action code | `site.update` |
| 29–30 | `entity_type`, `entity_id` | What it was about | `site`, `7` |
| 31–32 | `old_values`, `new_values` | Before and after (JSON objects in JSON files) | `{"city":"Seattle"}` |
| 33 | `error_message` | For errors: the exception and stack trace | |
| 34 | `audit_id` | The entry's ID in IPAM's database | `4182` |
| 35 | `category` | For operational messages: where in IPAM they came from | |
| 36–37 | `prev_hash`, `hash` | The tamper-evidence chain (section 7) | 64 hex characters each |

**What can't be captured, and why.**
- **A browser's own private (LAN) IP address.** Browsers don't reveal it, and the old trick that exposed it has been
  closed by browser makers for privacy reasons. The client IP is the address IPAM sees, after any trusted proxy.
- **Location from an IP address (country, city).** It needs an outside database that has to be kept current; the SIEM is
  the better place for it.

---

## 6. Event IDs

Every event has a permanent number, grouped by area like Windows event IDs. An ID is never reused or renumbered. New
events get new numbers.

| Range | Area | Examples | File |
|---|---|---|---|
| 1001–1007, 1031–1032 | Sign-in and sessions | 1001 Signed in · 1002 Sign-in failed · 1003 Signed out · 1004 Session rejected · 1005 Too many sign-in attempts · 1006 Password changed · 1007 Password reset · 1031 Page viewed · 1032 Session expired | access |
| 1010–1051 | Security controls | 1010 Blocked by the IP AllowList · 1011 Access denied · 1012 Request without the security header · 1020–1029 Sensitive views · 1030 Search · 1040–1043 IP AllowList changes · 1050 Organization Setting changed · 1051 Allowed-IP requirement changed | security |
| 2000s | Users, groups and access | 2001 User created · 2002 User changed · 2003 User's groups changed · 2004 User's workspaces changed · 2101–2106 Groups | security |
| 3000s | Network blocks and subnets | 3001 Network block created · 3010 Network split · 3013 Network details changed · 3020 Sub block created | payload |
| 4000s | Lists | 4001–4003 Sites · 4011–4013 Environments · 4021–4023 Divisions · 4031–4033 Products · 4041–4043 Block types | payload |
| 5000s | Workspaces | 5001–5003 Workspace created, changed, deleted (payload) · 5004–5005 Workspace members (security) | payload / security |
| 6000s | Export and import | 6001–6012 Exports · 6050 Template downloaded · 6101–6109 Imports | security |
| 7000s | Settings, database, backups, logging | 7001 Setting changed · 7020–7024 Database moved or copied · 7030 Log settings changed · 7031/7032 Debug on/off · 7033 Old log files deleted · 7034 Old audit entries purged · 7035 Log write failed · 7036 Log files checked · 7037 Log tampering found · 7038 Log files compressed · 7039 Log files archived · 7041 Log archiving failed · 7042 Old audit entries archived · 7043 Logging degraded · 7044 Logging restored · 7010/7011 Backups (app) · 7002 Logo and 7040 Reference data (payload) | security, app, payload |
| 9000s | System | 9001 IPAM started · 9002 IPAM stopped · 9003 Database upgraded · 9004 Startup blocked · 9005 Database unavailable (security) · 9101 API request (access) · 9102 App message · 9500 Unexpected error (app) · 9900 Debug detail (debug) | as shown |

Each area has an "other" event (x999) for anything without its own ID. The complete, current list, with each event's
description and file, is on **Administration → Log Settings → Event IDs**, and exports as CSV or JSON for building
alerts.

**Suggested alerts**

| Watch for | Why |
|---|---|
| 1002 more than 5 times in 10 minutes for one user or one client IP | Password guessing |
| Any 1005 | Automated guessing, already being slowed down |
| Any 1010, 1011 or 1012 | Someone outside their access, outside the allowed networks, or a forged request |
| 1050, 1040–1043, 1051 | The IP AllowList or its enforcement changed |
| 2003, 2105, 2106 involving the Administrators group | Privilege change |
| 6008 (users exported) or 6011 (audit log exported) | Sensitive data leaving |
| 7030, 7031, 7034 outside the daily clean-up | Logging changed, or history removed |
| Any 7035, 7037, 7041 or 7043 | Logging failed or degraded, log files were changed, or archiving failed |
| Any 9005 | IPAM couldn't use its database (also look at the database server's own logs, section 9) |
| A gap between 9002 and the next 9001 | IPAM was down; nothing was logged in between |
| Any 9004 or 9500 | A blocked start, or an unexpected error |

---

## 7. Tamper evidence

**How it works.**
- Every line carries two fingerprints:
  - `hash`, a SHA-256 fingerprint of everything on the line together with the fingerprint before it;
  - `prev_hash`, the `hash` of the line before it in the same file.
- The lines of each file form a chain, which carries on across days, restarts and file parts.
- **Changing** any value on a line makes its fingerprint stop matching its contents.
- **Deleting** or **inserting** a line breaks the link between neighbours.

**Checking.**
- **On screen:** Audit log → Tamper check → **Check the log files now** checks every JSON and CSV log file and shows
  each as Intact or Changed, with the line numbers that don't match. The check is itself recorded: event 7036 when
  everything is intact, 7037 (Failed) when something was changed.
- **On the server**, for the server administrator or a scheduled job:

  ```bash
  docker exec -it ipam dotnet Ipam.Web.dll verify-logs
  ```

  Or one file:

  ```bash
  docker exec -it ipam dotnet Ipam.Web.dll verify-logs /data/logs/ipam-security-20261017.json
  ```

  It lists every file as `OK` or `BROKEN` and ends with exit code 4 if anything was changed, so it can drive monitoring.

**What it does and doesn't do.** The chain shows that a file was altered; it can't stop someone with full control of the
server from altering it. The protection against that is to ship the files to the SIEM as they're written, so a copy
exists outside the server, and to keep the database audit log, a second, independent record of every change and
sign-in. Both are part of the recommended deployment.

---

## 8. Retention, compression and long-term archiving

Each log file has its own policy on **Administration → Log Settings**, one row per file, so a security file can be kept
for a year while debug detail goes after a week.

| Setting | What it does |
|---|---|
| **Keep for (days)** | How long the file stays in the log folder: 1 to 3,650 days. There is no other limit: disk space is the customer's to manage, and the page shows each file's size |
| **Compress after (days)** | After that many days the file is gzipped (`….json.gz`) and stays in the log folder, taking a fraction of the space. Blank: never. Compressed files can still be checked for tampering |
| **Archive** (Yes/No) | When "keep for" runs out: **Yes** moves the file, gzipped, to the archive folder for long-term storage; **No** deletes it |
| **Archive folder** | Required when Archive is Yes: a full path IPAM can write to, typically a mounted network share or object-storage gateway. IPAM tests it before saving |

**Defaults**

| File | Keep for | Compress after | When the days run out |
|---|---|---|---|
| access | 366 days | never | delete |
| payload | 91 days | never | delete |
| security | 366 days | never | delete |
| app | 32 days | never | delete |
| debug | 7 days | never | delete |
| Database audit log | 366 days | — | delete (or archive first, below) |

**How it runs**
- Once a day, never touching the current day's files.
- **Checked first:** before a file is compressed or archived, its fingerprint chain is checked. A broken chain is
  recorded as "log tampering found" (7037), and the file is still kept, so the evidence isn't lost.
- **Copied before removed:** an archived file is written to the archive and confirmed before it's removed from the
  log folder. If the archive can't be written, the file stays where it is, "log archiving failed" (7041) is recorded,
  and it's tried again the next day.
- **Everything is recorded:**
  - files compressed (7038), archived (7039) and deleted (7033);
  - audit entries archived (7042) and purged (7034).

  So the absence of old data is always explained.

**The database audit log** has its own row. With Archive on, entries past their days are first written to the archive
folder as a gzipped JSON-lines file (`ipam-dbaudit-purged-….json.gz`) and only then purged. If that file can't be
written, nothing is purged.

Long-term retention beyond the disk (the year or more some standards ask for) can be met with the archive, with the
SIEM, or both.


## 9. The database audit log, and the database server's own logs

**IPAM's database audit log** is a table in IPAM's own database: the history shown on the Audit log page (changes,
sign-ins and security events). It is IPAM's record, not the database server's.
- **It reaches the enterprise logging system already.** Every entry is copied, within about a second of being saved, to
  the access, payload or security log file, which the SIEM collects. The files are the extract; the database copy is a
  second, independent record.
- **Entries are kept 366 days by default** (30 to 3,650), and can be archived before they're purged (section 8).

**The database server's own events** happen outside IPAM, so IPAM can't record them: logins to PostgreSQL or SQL Server
(including failed ones), and changes made directly by a database administrator. These belong to the database server's
auditing, collected by the same SIEM:

| Database | Turn on | Records |
|---|---|---|
| PostgreSQL | `log_connections = on`, `log_disconnections = on`, `log_line_prefix` with user and host; the `pgaudit` extension for statements | Logins, failed logins, sessions, DDL and data changes made outside IPAM |
| SQL Server | SQL Server Audit, with a server audit specification for `FAILED_LOGIN_GROUP`, `SUCCESSFUL_LOGIN_GROUP` and a database audit specification for changes; or the error log's login auditing ("Both failed and successful logins") | Logins, failed logins, permission changes, direct changes |
| SQLite (default) | No database logins exist; the database is a file in IPAM's data folder | Protect the folder with file permissions (only the container's user); the host's auditd can watch it |

**What IPAM adds:**
- **"Database unavailable" (9005)** when IPAM can't reach or use its database (a refused login, the server down, the
  file locked), in the security log file, at most once a minute.
- **Least privilege:** IPAM's database account needs to create and change its own tables (for upgrades) and read and
  write its data; it needs no server-wide rights. The deployment guide gives the minimum grants.

---

## 10. Logs around IPAM: the server, the container, the proxy

IPAM's log files cover IPAM. A complete picture also includes what's around it. These are the customer's to collect,
usually with the same agent:

| Source | Where | What it shows |
|---|---|---|
| Container console | `docker logs ipam` (the Docker json-file driver) | IPAM's own lines, in the same JSON format. Our Docker compose files rotate it (50 MB × 5 files), so it can't fill the disk |
| Reverse proxy (nginx or Apache) | its access and error logs | TLS, the real client address, requests refused before they reach IPAM, unusual traffic |
| The host | journald, `/var/log/secure`, auditd | Who logged on to the server, `sudo` use, access to IPAM's data and log folders |
| The Docker daemon | journald (`docker.service`) | Containers started, stopped and replaced, images pulled |
| firewalld and SELinux | journald, `/var/log/audit/audit.log` | Blocked connections, policy denials |
| The time service | chrony (journald) | Clock problems, which matter for lining up events across systems |
| The database server | section 9 | Database logins and direct changes |
| IPAM's startup log | `/data/logs/startup-YYYYMMDD.log` | Bootstrap diagnostics written even if everything else fails (also on the console) |


---

## 11. Bringing the logs into a SIEM

The files are written to the log folder: `/data/logs` inside the container, `/opt/ipam/data/logs` on the host with the
standard deployment, unless an administrator chose another folder. They're append-only and can be read while IPAM
writes them, which is what forwarders expect.

**Splunk Universal Forwarder** (`inputs.conf`), one index per file:
```
[monitor:///opt/ipam/data/logs/ipam-access-*.json]
sourcetype = _json
index = ipam_access

[monitor:///opt/ipam/data/logs/ipam-payload-*.json]
sourcetype = _json
index = ipam_payload

[monitor:///opt/ipam/data/logs/ipam-security-*.json]
sourcetype = _json
index = ipam_security

[monitor:///opt/ipam/data/logs/ipam-app-*.json]
sourcetype = _json
index = ipam_app
```
For the timestamp, `props.conf`: `TIME_PREFIX = "timestamp":"`, `TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ`, `TZ = UTC`.
Index-level roles then give each team exactly its file.

**Datadog agent** (`conf.d/ipam.d/conf.yaml`):
```yaml
logs:
  - type: file
    path: /opt/ipam/data/logs/ipam-security-*.json
    service: ipam
    source: ipam
    tags: ["ipam_log:security"]
  - type: file
    path: /opt/ipam/data/logs/ipam-access-*.json
    service: ipam
    source: ipam
    tags: ["ipam_log:access"]
```
(and likewise for payload and app), or the agent's container log collection, since every console line is the same JSON.

**Fluent Bit** (to Elastic, OpenSearch, Azure Monitor and others):
```
[INPUT]
    Name   tail
    Path   /opt/ipam/data/logs/ipam-*.json
    Parser json
    Tag    ipam.*
```
Route on the `log_type` field.

**Microsoft Sentinel / Azure Monitor:** the Azure Monitor Agent with a custom JSON log table for each file.

Sending logs straight from IPAM to syslog over TLS, a Splunk HTTP Event Collector or the Datadog intake API is on the
roadmap (section 16).

---

## 12. Investigations: what a security team can answer

| Question | Where to look |
|---|---|
| Who signed in as this user, from where, and with which browser? | access: 1001 with `user`, `client_ip`, `browser`, `os`, `session_id` |
| Has someone been guessing passwords? | access: 1002 and 1005 by `client_ip` and `user` |
| What did this person do in that session? | Every file: filter on `session_id`. Screens (1031), calls (9101), changes (payload), sensitive views, exports (security) |
| Who changed this subnet, when, and what was it before? | payload: `entity_id`, with `old_values` → `new_values`. Or the Audit log page, "Change history" on the subnet |
| Who gave this person administrator rights? | security: 2003 and 2105 on the Administrators group |
| Did anyone take the user list or the audit log out of IPAM? | security: 6008, 6011 |
| Did anyone try something they weren't allowed to? | security: 1011 (with the role needed), 1012 |
| Who changed the IP AllowList, or turned enforcement off? | security: 1040–1043, 1050 |
| Did anyone look at the audit log or the users? | security: 1020, 1021 |
| Was logging changed, turned down or tampered with? | security: 7030, 7031/7032, 7033/7034, 7035, 7037, and a gap between 9002 and 9001 |
| Did the error this user reported happen, and why? | The request ID on their screen → app (9500, with the stack trace) and access (9101) |

---

## 13. Protecting the logs, and what is never logged

**Never logged.**
- Passwords: sign-in, change, reset, temporary passwords for new users.
- Password hashes and the security stamps that invalidate sessions.
- Sign-in cookies and the `Authorization` header (removed from the debug lines too).
- Database connection strings and their passwords.

An automated test signs in, creates users with temporary and permanent passwords and fails a sign-in on purpose, then
checks every log file for those strings. A second test does the same for database server passwords used on the
Database page. API request lines record the path without its query string; only debug lines, while debug logging is on,
include the query string.

**Personal data in the logs.** Usernames, display names, client IP addresses and browser details are personal data in
many jurisdictions. They're recorded because an investigation needs them. Retention limits (section 8) and per-file
access in the SIEM let the organization keep them only as long, and only for the people, it needs.

**Who can change logging.**
- **Administrators only** can change Log Settings (the folder, formats, retention, which logs are written, debug).
  Every change is recorded with its old and new values.
- **Audit, access, payload and security events can't be switched off.** The app log and the per-request lines can be
  reduced; errors are always written.
- **Debug logging** goes to separate files and runs for 24 hours, or until a chosen time at most 7 days ahead, then
  turns itself off and records that it did.

**The log folder.**
- **The default** is inside IPAM's data folder (a mounted volume in the container).
- **Changing it:** an administrator can choose another folder. IPAM tests that it can write there before saving, and
  warns when a container folder isn't on a mounted volume.
- **Server access:** the host's file permissions apply, so ordinary users of the server needn't be able to read the
  folder. Forwarders need read access only.

**When logging can't write.** IPAM keeps working. The line still goes to the console, the failure goes to the startup
log, and a "log write failed" event (7035) is recorded once the cause is cleared. Log Settings shows the last failure.

**The Logging status bar.** Administrators see a bar at the top of every page.
- **Green, "Logging status = Successful",** while everything works.
- **Red, "Logging status = Down or Degraded",** with the reason and a link to Log Settings, when any of these is true:

| Condition | Why it matters |
|---|---|
| A log line couldn't be written in the last 10 minutes | A full disk, a lost network share, changed permissions: events are reaching the console but not the files |
| The log folder's disk has under 1 GB or 5% free | An early warning, before writes start failing |
| Audit entries have waited more than 2 minutes to reach the files, or the database can't be read | The SIEM isn't getting changes and security events on time |
| Compressing or archiving failed in the last 24 hours | Old files are piling up, or long-term storage is unreachable |

Each change of status is itself recorded:
- "Logging degraded" (7043, Failed), with the reasons;
- "Logging restored" (7044) when it's back.

If the database itself is down, the change still goes to the log files and the console. A SIEM alert on 7043 tells the
security team without anyone having to look at the screen.

---

## 14. The rest of IPAM's security controls

Logging is one layer. These are the others a reviewer usually asks about.

**Sign-in and sessions**
- Passwords are stored as PBKDF2-SHA256 hashes with a random 16-byte salt and 600,000 iterations (the current OWASP
  recommendation). Passwords are at least 12 characters.
- A new user's password is temporary: they must choose their own at first sign-in. The first administrator's one-time
  password is written to a file on the server, which is deleted once it's been changed.
- A failed sign-in says the same thing, and takes the same time, whether the user exists or not, so usernames can't be
  discovered.
- Sign-ins from one address are limited to 10 a minute.
- The sign-in cookie is encrypted, `HttpOnly` (unreadable by scripts), `SameSite=Strict`, and `Secure` behind HTTPS. It
  expires after a period of inactivity (8 hours by default, configurable).
- Each sign-in has its own session ID, on every log line.
- The account is checked on every request. Disabling an account or resetting its password signs it out everywhere
  immediately, and what a user may do is read from their groups on every request, so a change of role applies at once.

**Access control**
- About two dozen built-in roles, each allowing one kind of work, bundled into groups. Every API route states the role
  it needs, and an automated test fails if any route doesn't.
- A small set of guard rails is enforced by the server, not just the screens:
  - only Administrators can make someone an Administrator;
  - nobody but an Administrator changes their own access;
  - the default administrator account can't be altered;
  - there's always at least one active Administrator.
- **Workspaces** separate network plans. A user can be limited to the workspaces they need, and the limit applies to
  every list, search and export.

**Network access to IPAM**
- **The IP AllowList:** IPAM can be limited to approved networks, as address ranges or CIDRs, permanent or with an end
  date.
- **Lock-out protection:** enforcement can only be turned on while the administrator's own address is allowed, and a
  change that would lock out the person making it is refused. A documented recovery command exists for the server
  administrator.

**The web application**
- **Anti-forgery:** every change needs a custom header that another website can't send, on top of the `SameSite`
  cookie.
- **Response headers:** a strict Content-Security-Policy (no inline scripts, no third-party content),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and no caching of API
  responses.
- **No HTML injection:** the screens never insert user data as HTML.
- **CSV exports:** text that a spreadsheet could take for a formula is neutralized.

**Data integrity and operations**
- **Changes:** every change runs in one transaction with its audit entry, re-checks the data inside the transaction,
  and is refused if someone else changed the same record in the meantime.
- **Startup safety:** IPAM refuses to start on a data folder that would be lost when the container is replaced,
  refuses a database from a newer version, and backs the database up before any upgrade.
- **Databases:** SQLite (with scheduled backups), or the customer's PostgreSQL or SQL Server, where backups follow the
  customer's own policy.

---

## 15. How the design supports common frameworks

IPAM is software, not an organization, so it can't itself be certified against a standard. Compliance comes from how a
customer deploys and runs it. The table shows which requirements IPAM's design helps a customer meet. The references are
to the controls as commonly cited; your assessor's reading of your scope is what counts.

| Framework | Requirement (summary) | How IPAM helps |
|---|---|---|
| **NIST SP 800-53 Rev. 5** | AU-2 Event logging | The event catalog defines what is logged; audit and security events can't be switched off |
| | AU-3 Content of audit records | What, when, where, source, outcome and identity on every line (section 5) |
| | AU-6 Review, analysis and reporting | The Audit log page (filters, per-column search, export), SIEM-ready files, event IDs for alerts |
| | AU-8 Time stamps | UTC with milliseconds everywhere |
| | AU-9 Protection of audit information | Hash chain, the tamper check, Administrators only for logging, secrets never logged |
| | AU-11 Audit record retention | Per-file retention up to 3,650 days, compression, long-term archiving, database audit log for 366 days by default and archived before purging, every purge logged |
| | AU-12 Audit record generation | Generated by the server for every API route and change |
| | AC-2 Account management | Every account, group and access change recorded |
| | AC-7 Unsuccessful logon attempts | Failed sign-ins recorded; rate limiting per address (see section 16 for account lock-out) |
| **ISO/IEC 27001:2022, Annex A** | 8.15 Logging | Five log files, fixed fields, tamper evidence, retention |
| | 8.16 Monitoring activities | Event IDs and suggested alerts for a SIEM |
| | 8.17 Clock synchronization | UTC timestamps; the host's time service (for example chrony on RHEL) keeps the clock |
| | 5.15 / 8.2 Access control, privileged access | Roles and groups, guard rails on administrator rights, every change recorded |
| | 8.5 Secure authentication | PBKDF2 hashing, generic sign-in errors, rate limiting, secure cookie |
| **SOC 2 (Trust Services Criteria)** | CC6.1–CC6.3 Logical access | Role-based access, least privilege, immediate effect of revocation |
| | CC7.2 Monitoring of system components | Security events and the SIEM files |
| | CC7.3 Evaluating security events | Event IDs, statuses (FAILED and DENIED), investigation fields |
| **PCI DSS v4.0** | 10.2 Audit logs capture user activity | Sign-ins, access to audit trails (1020), invalid access attempts (1011, 1002), changes to identification and authentication (2000s, 1006–1007), changes to logging (7030–7034) |
| | 10.3 Audit logs are protected | Hash chain, tamper check, separated access |
| | 10.4 Audit logs are reviewed | Audit log page and SIEM alerts |
| | 10.5 Audit log history retained | Access and security files a year on disk by default (up to ten), compressed after a set age; older files moved to long-term storage; a year in the database; the SIEM as well |
| | 10.6 Time synchronization | UTC timestamps from a synchronized host |
| **CIS Controls v8** | 8.2 Collect audit logs; 8.5 Collect detailed logs; 8.9 Centralize; 8.10 Retain | Detailed fields, SIEM-ready files, retention settings |
| **HIPAA Security Rule** | §164.312(b) Audit controls | Recorded activity on the system, if IPAM is in scope |
| **GDPR / privacy laws** | Art. 5 data minimization and storage limitation; Art. 32 security of processing | Retention limits, per-audience files, no secrets, personal data only where an investigation needs it |

---

## 16. Known limits and the roadmap

We'd rather a reviewer hear these from us.

| Area | Today | Planned or recommended |
|---|---|---|
| Sending logs to a SIEM | Files and console, collected by the customer's agent (Splunk forwarder, Datadog agent, Fluent Bit) | Direct sending to syslog over TLS, Splunk HEC and the Datadog API (planned enhancement) |
| Single sign-on and MFA | IPAM's own accounts and passwords | Single sign-on, likely Microsoft Entra ID, which brings the organization's MFA (planned) |
| Account lock-out | Sign-ins limited to 10 a minute per address; every failure recorded | A per-account lock-out policy (under consideration) |
| Immutable storage | Tamper-evident (the chain shows changes); not tamper-proof on the server itself | Ship to the SIEM as written; use WORM or immutable storage there |
| Screen views | Reported by the browser; a determined user could block them | The API request lines are the authoritative record of what was fetched |
| Time source | The server's clock | Run a time service on the host (chrony on RHEL), pointed at the organization's time servers |
| IPv6 | IPAM manages IPv4; the IP AllowList is IPv4 | IPv6 is on the longer-term roadmap |

---

## 17. Questions security reviewers ask

**Can an administrator delete audit history without it showing?**
- Not without leaving a trace.
- Retention purges are recorded (7034), and changing the retention is recorded (7030).
- The files are tamper-evident, and their copies in the SIEM are outside IPAM's reach.
- Someone with direct access to the server's database or file system works outside the application. The hash chain
  and the SIEM copy are the controls against that.

**Can logging be turned off?**
- Audit, access, payload and security events, no.
- The app log and the per-request lines can be reduced; errors are always written.
- Every change to logging is itself recorded.

**Is debug logging a risk?**
- It's off by default and only Administrators can turn it on.
- It writes to separate files, strips cookies and credentials, and runs at most 7 days before turning itself off.
- Turning it on and off is recorded.

**Where do the database server's own login events go?** To the database server's audit log, not IPAM's: IPAM never
sees a login to PostgreSQL or SQL Server. Section 9 lists what to turn on. IPAM records when it can't use its database
(9005).

**How long can logs be kept?** Up to 3,650 days on disk per file, compressed after a chosen age, and moved to long-term
storage after that if wanted (section 8). There's no technical limit beyond disk space.

**How quickly do events reach the files?** Immediately for access, app and debug lines. Database-recorded events within
about a second of being saved.

**Are timestamps in local time?** No: UTC, with milliseconds, everywhere: files, console, database.

**What if the disk fills up?** Writes fail safely: IPAM keeps running, the failure goes to the console and startup log,
and a "log write failed" event is recorded once space is available. Before that, the Logging status bar turns red
when the disk drops under 1 GB or 5% free, and "Logging degraded" (7043) is recorded. Retention, compression,
archiving, the 100 MB file parts and the rotated container console keep usage predictable.

**Can our SOC see the events without access to IPAM?** Yes. The files and console are designed for collection. The SOC
needs read access to the log folder, or the container's console, not an IPAM account.

**Where do I find the full list of events?** Administration → Log Settings → Event IDs (exportable), and
`docs/LOGGING.md` in the product documentation, which also has the field reference and collector set-ups.

---

*IPAM's documentation also includes the User Guide (every screen), the Deployment Guide (installation, reverse proxy,
backups, upgrades) and the logging reference (`docs/LOGGING.md`).*
