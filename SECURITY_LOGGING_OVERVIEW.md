# IPAM — Security, Privacy and Logging Overview

**For CISOs, legal and privacy teams, security architects, SOC analysts and auditors evaluating IPAM**

Version 0.1.0 · October 2026

---

## Contents

**Part A: for everyone**
1. [Executive summary](#1-executive-summary)
2. [Who should read what](#2-who-should-read-what)
3. [What IPAM holds, and how sensitive it is](#3-what-ipam-holds-and-how-sensitive-it-is)
4. [Where the data lives: self-hosted, owned by you, no telemetry](#4-where-the-data-lives-self-hosted-owned-by-you-no-telemetry)
5. [Protecting the network design as intellectual property](#5-protecting-the-network-design-as-intellectual-property)
6. [Security by design: the principles](#6-security-by-design-the-principles)

**Part B: security controls**
7. [Identity, sign-in and sessions](#7-identity-sign-in-and-sessions)
8. [Access control: roles, groups and workspaces](#8-access-control-roles-groups-and-workspaces)
9. [Network access: the IP Allow List](#9-network-access-the-ip-allow-list)
10. [The web application and its API](#10-the-web-application-and-its-api)
11. [Encryption in transit and at rest](#11-encryption-in-transit-and-at-rest)
12. [Backups, recovery and continuity](#12-backups-recovery-and-continuity)
13. [Hosting: the container and the server](#13-hosting-the-container-and-the-server)
14. [Secure development and the supply chain](#14-secure-development-and-the-supply-chain)

**Part C: logging and monitoring**
15. [What IPAM records](#15-what-ipam-records)
16. [Five log files, one audience each](#16-five-log-files-one-audience-each)
17. [Every line: the field dictionary](#17-every-line-the-field-dictionary)
18. [Event IDs and suggested alerts](#18-event-ids-and-suggested-alerts)
19. [Tamper evidence](#19-tamper-evidence)
20. [Retention, compression and long-term archiving](#20-retention-compression-and-long-term-archiving)
21. [The database audit log, and the database server's own logs](#21-the-database-audit-log-and-the-database-servers-own-logs)
22. [Logs around IPAM: the server, the container, the proxy](#22-logs-around-ipam-the-server-the-container-the-proxy)
23. [Bringing the logs into a SIEM](#23-bringing-the-logs-into-a-siem)
24. [Investigations: what a security team can answer](#24-investigations-what-a-security-team-can-answer)
25. [Protecting the logs, and what is never logged](#25-protecting-the-logs-and-what-is-never-logged)

**Part D: privacy, governance and assurance**
26. [Privacy and personal data](#26-privacy-and-personal-data)
27. [Incident response and recovery](#27-incident-response-and-recovery)
28. [Shared responsibility: IPAM and the customer](#28-shared-responsibility-ipam-and-the-customer)
29. [How the design supports common frameworks](#29-how-the-design-supports-common-frameworks)
30. [Known limits and the roadmap](#30-known-limits-and-the-roadmap)
31. [Questions reviewers ask](#31-questions-reviewers-ask)

This document is also in IPAM itself: **Help & Reference → Security, Privacy & Logging Overview**, with a Download
button.

---

# Part A: for everyone

## 1. Executive summary

IPAM (IP Address Management) keeps an organization's network plan: its network blocks and subnets, its sites and their
addresses, its circuits with their contracts and costs, its vendors, and the people and teams responsible for them.
That plan is a map of the network. An attacker would value it, a competitor would value the commercial terms in it, and
the organization depends on it being right. IPAM treats it as intellectual property and as confidential business
information.

**In brief:**
- **You keep the data.** IPAM runs on your own server, in your own network, with your own database. It sends nothing to
  its maker: no usage data, no telemetry, no licence check, no outside scripts or fonts. Its only outbound connections
  are to the mail service you configure and, if an Administrator turns them on, registry lookups of public ranges.
- **Nobody sees more than their job needs.** 44 built-in roles, bundled into groups; workspaces that separate network
  plans; guard rails on administrator rights enforced by the server; every API route states the role it needs, and an
  automated test fails if one doesn't.
- **Sign-in is controlled.** Strong passwords (12+ characters, no names, no common passwords), expiry and reuse rules,
  account lockout, rate limiting, an idle timeout, a maximum session length, a nightly sign-out, and an instant
  "sign everyone out" for incidents.
- **Access can be limited to your networks.** The IP Allow List restricts IPAM to approved address ranges, for everyone
  or per user.
- **Everything is recorded.** Every sign-in, every change (with before and after values), every look at sensitive
  information, every export and every change to a security setting is recorded twice: in IPAM's database and in log
  files built for your SIEM. 227 events, each with a permanent ID. Every line is chained to the one before it with
  SHA-256, so a changed, deleted or inserted line can be found.
- **Secrets stay secret.** Passwords are stored only as PBKDF2 hashes (600,000 iterations). Passwords, cookies,
  connection strings and mail credentials are never written to a log, and automated tests check it. Mail credentials are
  encrypted at rest.
- **The limits are stated plainly.** The database, backups and log files are not encrypted by IPAM itself; disk or
  database encryption is the customer's (section 11). Single sign-on and multi-factor sign-in are on the roadmap
  (section 30).

**At a glance**

| | |
|---|---|
| Deployment | Self-hosted: one Docker container on the customer's Linux server, behind the customer's HTTPS reverse proxy |
| Data location | The customer's server and database (SQLite, PostgreSQL or SQL Server). Nothing is held by the maker |
| Outbound connections | The mail service the customer configures (an SMTP relay, or Microsoft 365); registry lookups of public ranges (RDAP, off by default) |
| Authentication | IPAM accounts; PBKDF2-SHA256 hashes; password rules, expiry, history and lockout. SSO and MFA planned |
| Sessions | Idle timeout (default 30 min), maximum length (default 12 h), nightly sign-out, Clear All, enforced by the server |
| Authorization | 44 built-in roles in groups, plus workspaces; every API route checked; changes apply on the next request |
| Network restriction | IP Allow List (ranges or CIDRs, permanent or temporary), with lock-out protection |
| Web protections | Strict Content-Security-Policy, anti-forgery header, `SameSite=Strict` `HttpOnly` cookie, no HTML injection |
| In transit | TLS 1.2 / 1.3 and HSTS at the reverse proxy; the app port is published on 127.0.0.1 only |
| At rest | Mail credentials encrypted; database, backups and logs rely on the customer's disk or database encryption |
| Logging | Database audit log plus five SIEM-ready files (JSON, CSV or key=value), 37 fixed fields, UTC to the millisecond |
| Tamper evidence | SHA-256 hash chain on every line; an on-screen check and a server command |
| Retention | Per file, 1 to 3,650 days; compression; long-term archive; database audit log 30 to 3,650 days |
| Is logging working? | A Logging status bar for Administrators on every page; each change of status is an event |

---

## 2. Who should read what

| Reader | Start with | Then |
|---|---|---|
| **CISO** | 1 Executive summary, 5 Intellectual property | 11 Encryption, 28 Shared responsibility, 30 Known limits |
| **Legal and privacy** | 3 What IPAM holds, 4 Where the data lives | 26 Privacy, 20 Retention, 31 Questions |
| **Security architect** | 7 to 14 (all the controls) | 28 Shared responsibility, 29 Frameworks |
| **SOC and incident response** | 18 Event IDs and alerts, 24 Investigations | 23 SIEM, 27 Incident response |
| **Auditor or assessor** | 29 Frameworks | 15 to 21 (logging), 19 Tamper evidence |
| **Server administrator** | 13 Hosting, 12 Backups | 22 Logs around IPAM, 23 SIEM |

---

## 3. What IPAM holds, and how sensitive it is

IPAM holds no payment card data, no health data, no credentials for network devices, and nothing gathered from the
network: it never scans, pings or queries the network. Everything in it was typed or imported by its users.

| Data | Examples | Sensitivity | Who can see it |
|---|---|---|---|
| **Network design** | Network blocks and subnets, prefixes, gateways, VLANs, names, notes, cloud providers, block types, linked networks, tags | **Confidential.** A map of the network: valuable to an attacker | Network Block Viewer role, and only in the workspaces the user may see |
| **Sites** | Site codes, names, location types, street addresses | **Confidential.** Physical locations of network equipment | List Viewer role |
| **Circuits and contracts** | Circuit references, providers, types, bandwidth, A and Z sides, account numbers, order, install, renewal and contract end dates, auto-renewal, notice periods, monthly cost | **Confidential and commercially sensitive.** Supplier terms and costs | Circuit roles, in the circuit's workspace |
| **Vendors and contacts** | Vendor names and websites; each vendor's representatives (name, phone, email) | **Confidential, includes personal data** | List Viewer role |
| **Whitelisting requests** | Which customers whitelist our public IPs for which Product URLs; each request's company, contact name and email, ticket number and system, status, dates and notes | **Confidential, includes personal data** | Whitelisting Request roles |
| **VPN Services** | Each VPN's name, purpose, status and sides: sites, peer, NAT and end point IPs, listening ports, the customer's contact name and email, and ticket references. **No pre-shared keys, certificates or passwords: IPAM has no field for them** | **Confidential, includes personal data.** A map of connections into partner networks | VPN Services roles |
| **Service IP Mappings** | How each service's traffic travels from its public IP through each stage (NAT, load balancer, servers): the IPs of every hop, ports and protocols, notes | **Confidential.** A map of how the public services reach the servers | Service IP Mapping roles |
| **Lists** | Environments, divisions, products, IP Use Types, circuit providers and types, VPN Service Purposes; Product URLs (each product's URLs, the site serving them and their public IPs) | Internal | List Viewer role |
| **People** | Users' email, first and last name, display name, username, time zone, groups and roles; email contacts and distribution groups | **Personal data** | Users and groups roles; Email Recipients roles |
| **Security configuration** | Roles and groups, IP Allow List, Organization Configs, session timeouts, log settings | **Restricted** | Administrators (and the matching view roles) |
| **Audit history and logs** | Who did what, when, from which address, with before and after values | **Restricted, includes personal data** | Audit Log Viewer role; log files: the server and the SIEM |
| **Secrets** | Password hashes, mail passwords and client secrets | **Secret** | Never shown; hashes and encrypted values only |

The organization should classify IPAM, its database, its backups and its log files at the level of the most sensitive
item above: in most organizations, **Confidential**.

---

## 4. Where the data lives: self-hosted, owned by you, no telemetry

- **Self-hosted.** IPAM is a single Docker container that the customer runs on their own server (the reference platform
  is Red Hat Enterprise Linux with Docker), behind their own HTTPS reverse proxy. There is no software-as-a-service
  version and no hosted component.
- **Your database.** Data is kept in SQLite (a file in IPAM's data folder) or in the customer's own PostgreSQL or SQL
  Server. The customer chooses the location, and so the jurisdiction.
- **Nothing goes to the maker.** IPAM has no telemetry, no usage reporting, no crash reporting, no licence server, no
  update check and no remote support channel. The .NET tooling's own telemetry is switched off in the image.
- **No third-party content.** Every script, stylesheet, icon and font is served by IPAM itself (Bootstrap and the Tabler
  icons are bundled). The Content-Security-Policy forbids loading anything from elsewhere, so the browser can't be made
  to contact another site either.
- **Outbound connections** go to the mail service the customer configures, for notifications and test emails:
  their own SMTP relay, or Microsoft 365 (SMTP with OAuth, or Microsoft Graph; both need Microsoft's sign-in service).
- **Registry lookups** (Administration → Registry Lookups, off by default) ask IANA and the five regional internet
  registries over RDAP (HTTPS) who a public range is registered to. Only public network addresses and prefixes are
  sent, never private ones, names or other data. An outbound proxy can be set, and each settings change is audited
  (7060).
- With email not configured and registry lookups off, IPAM makes no outbound connections at all.
- **Links, not content.** The reference pages link to RFCs and Wikipedia; those open only when a user clicks them.
- **No sub-processors.** The maker processes no customer data, so there are none to list.
- **The customer owns everything** IPAM stores: the data, the audit history and the logs. Every list can be exported as
  CSV or JSON at any time, and the database is a standard SQLite, PostgreSQL or SQL Server database.

---

## 5. Protecting the network design as intellectual property

The network design, and the commercial information around it, is protected in layers. Each layer works on its own;
together they mean that taking the data needs a valid account, the right role, the right workspace, an allowed network
and an active session, and leaves a record.

| Layer | What it does | Section |
|---|---|---|
| **Who can reach IPAM** | The IP Allow List limits IPAM to approved networks; the app port is published on the server only, behind HTTPS | 9, 13 |
| **Who can sign in** | Individual accounts, strong passwords, lockout, rate limiting; disabled accounts are refused at once | 7 |
| **How long a session lasts** | Idle timeout, maximum length, nightly sign-out, Clear All for incidents | 7 |
| **What each person may see** | Least-privilege roles; view and edit are separate roles; lists, circuits and networks each have their own | 8 |
| **Which plans each person may see** | Workspaces separate network plans, for example by business unit or an acquired company; other workspaces aren't revealed, not even that a network exists | 8 |
| **What can leave** | Export needs the Export role **and** the right view role; every export is recorded with what, format, filters and row count; CSV is protected against formula injection | 10, 15 |
| **What is recorded** | Every view of sensitive pages, every search (with its terms), every change, every export | 15 |
| **Whether the record can be trusted** | Hash chain on every log line, an on-screen tamper check, copies in the SIEM | 19, 23 |
| **What a stolen copy reveals** | Mail credentials are encrypted and passwords are hashed; the rest depends on the customer's disk, database and backup encryption | 11, 12 |

---

## 6. Security by design: the principles

Security wasn't added at the end. A few rules apply to every part of the app.

1. **Deny by default.** Every API route states the role it needs. A route without a rule fails an automated test before
   it can ship. The screens hide or lock what a user can't do, but the server decides.
2. **Least privilege.** Roles each allow one kind of work. Viewing and changing are separate. Administrator rights are
   protected by guard rails the server enforces.
3. **Record the action at the moment it happens, in the same transaction.** A change and its audit entry are saved
   together or not at all. A cancelled change leaves none.
4. **Every event has a permanent identity.** Each kind of event has a fixed ID that never changes meaning, so alerts and
   saved searches keep working across upgrades.
5. **One format, every field, every line.** Every log line has the same fields in the same order. A field with nothing to
   say is empty rather than missing.
6. **Separate by audience.** Five log files, so each team can be given exactly the events it needs.
7. **Show tampering.** Every log line carries a fingerprint chained to the one before it.
8. **Never record secrets.** Passwords, hashes, cookies and connection strings stay out of every log, and automated tests
   check it.
9. **Fail safe, and say so.** If logging can't write, IPAM keeps working, writes to the console and the startup log,
   records the failure once it can, and shows Administrators a red Logging status bar.
10. **Time is UTC, to the millisecond, everywhere.** Events line up with firewalls, directories and other systems.
11. **No user data as code.** The screens never insert user data as HTML, and the browser may run only IPAM's own
    scripts.

---

# Part B: security controls

## 7. Identity, sign-in and sessions

**Accounts**
- Every person has their own account. Shared accounts aren't needed: every role can be given to any number of people.
- A user is identified by an email address (unique, ignoring case) and a username generated from it once, which never
  changes, so the audit history always points to the same person. Sign-in accepts either.
- **Accounts are deactivated, never deleted**, so the audit history keeps its meaning. A deactivated account can't sign
  in and its sessions end at once.
- A new user's password is temporary: they must choose their own at first sign-in, and can reach nothing else until
  they have.
- The first administrator's one-time password is written to a file on the server, which is deleted once it's been
  changed.
- Each user can see, on **My Account**, their own recent sign-ins and every role they have, with what grants it.

**Passwords**
- Stored as PBKDF2-SHA256 hashes with a random 16-byte salt and 600,000 iterations (the current OWASP recommendation).
  The password itself is never stored or logged.
- **Requirements:** at least 12 characters, with an upper-case letter, a lower-case letter, a number and a symbol; not
  containing the user's username, email name, first or last name; not a common password (a built-in list, also checked
  with letters swapped for look-alike numbers and symbols). The screens show the requirements as a live checklist with a
  strength bar, and can generate a strong password. The server checks the same rules.
- **Expiry:** passwords expire after 90 days (Organization Config 005; 0 = never), with a reminder in the last 14 days.
  The built-in `admin` account doesn't expire.
- **History:** the last 5 passwords can't be reused.

**Guessing and lockout**
- **Lockout:** 5 wrong passwords in a row lock the account for 15 minutes (Organization Configs 006 and 007). Attempts
  while locked aren't checked or counted. Unknown usernames lock the same way, so the lockout doesn't reveal which names
  exist. The user is emailed when their account locks.
- The lock ends when its time runs out, or when an Administrator unlocks the account or resets its password. For the
  built-in `admin` account there is also a support procedure that unlocks it at the database (not published; contact
  support).
- **Rate limiting:** sign-ins from one address are limited to 10 a minute.
- **No user discovery:** a failed sign-in says the same thing, and takes the same time, whether the user exists or not.

**Backup Administrator**
- A separate role for unlocking, reactivating or resetting the password of another Administrator, for when the only
  other Administrator is locked out.
- At sign-in its holder chooses between regular access and backup administrator work. The work allows only those three
  actions, never on the built-in `admin` or their own account, and ends after 15 minutes.
- Every other Administrator is emailed when it starts and at each action. If the email fails, the work goes ahead, the
  failure is recorded (8011), and Administrators see a red banner until it's dismissed.

**The sign-in cookie**
- Encrypted and signed with the server's Data Protection keys; `HttpOnly` (scripts can't read it); `SameSite=Strict`;
  `Secure` behind HTTPS.
- Each sign-in has its own session ID, on every log line.
- **Checked on every request:** the account must still be active, and its password unchanged since the sign-in.
  Disabling an account or resetting its password signs it out everywhere at once. Roles are read from the user's groups
  and directly given roles on every request, so a change of access applies at the next click.

**Session limits** (Administration → Session Timeouts, Administrators only). All are enforced by the server on every
request, never by the browser, and apply at once to every open session, with no restart.

| Control | Default | What it does | Recorded |
|---|---|---|---|
| **Idle timeout** | 30 minutes (5 to 1,440) | A sign-in ends after this long without activity | 7003 (change), 1032 (a session ended) |
| **Maximum session length** | 12 hours (1 to 24) | A sign-in ends this long after it began, however active the user is | 7003, 1032 |
| **Nightly sign-out** | On | Every sign-in ends at 23:59:59 in the organization's time zone, so no session runs into the next day | 7003, 1032 |
| **Clear All Session Tokens** | (a button) | Ends every signed-in session at once, the Administrator's own included; everyone must sign in again. For incidents or after a change that must apply to everyone now | 7004 |
| **Activity timeout override** (per user) | None | An Administrator gives one user their own idle timeout (5 to 720 minutes), which also lifts the maximum session length for that user, for example a wall display or an operations screen. Never on the Administrator's own account, and confirmed by typing YES. The nightly sign-out and Clear All still apply | 2009 |

- The **organization's time zone** (Administration → Organization Time Zone) sets when the nightly sign-out happens and
  when temporary IP Allow List entries end. Changing it is recorded (1050).
- **The warning:** the browser warns the user two minutes before a limit, with a countdown, and *Stay signed in* where the
  limit allows it. The countdown runs in the browser; when it ends, the browser makes one session check
  (`GET /api/auth/session`), which the server never counts as activity.
  **An unattended screen can't keep itself signed in:** IPAM sends nothing in the background. An automated test checks
  this.
- An ended session is recorded in the access log (1032), with which limit ended it.

---

## 8. Access control: roles, groups and workspaces

**Roles and groups**
- **44 built-in roles**, each allowing one kind of work: for example Network Block Viewer and Network Block
  Administrator, the Circuit roles, a viewer and an administrator role for each list, Users, Groups, Email Recipients,
  Audit Log Viewer, Export, Import, Backup Administrator and Administrator. Roles are defined in the code and can't be
  changed, so their meaning is fixed and reviewable on the read-only **Roles** page.
- Roles are given through **groups** (a person gets the roles of every enabled group they belong to), or directly to a
  user. Every change of membership or role is recorded (2003, 2007, 2008, 2101 to 2106).
- **Administrator** includes every role, except changing the built-in `admin` account's password, which only its own
  role allows.

**Guard rails** enforced by the server, not just the screens:
- only Administrators can make someone an Administrator, or change an Administrator;
- nobody but an Administrator changes their own access;
- the built-in `admin` account can't be altered, only have its password reset by its own role;
- there's always at least one active Administrator.

**Proxy access (viewing IPAM as a user)**
- To troubleshoot without a screen share, someone with the **User Proxy Access** role can view IPAM as another user:
  their menu, locks, workspaces and pages, exactly as they see them. It starts from the user's row on the Users page and
  needs a reason, for example a ticket number.
- **Read-only.** While it's on, the server refuses every change (1019), whatever the user's own roles would allow.
- **It can't gain access.** Never as an Administrator, the built-in `admin` account or yourself, and only as someone
  whose roles and workspaces the viewer already has. This is checked at the start and again on every request.
- **It ends** after 30 minutes, with Stop, at sign-out, or as soon as the access behind it changes (1018). A red banner
  shows it on every page.
- **Both people are recorded.** Every log line and audit entry has the user in `user` and the viewer in `proxy_by`, with
  the reason in `proxy_reason`. The start and end are the viewer's own entries (1017, 1018).
- **The user is told:** a notice at their next sign-in, the full list on My Account, and an email when email is set up.

**Workspaces**
- Workspaces separate network plans, for example by business unit, region, or a newly acquired company whose addresses
  overlap.
- A user can be limited to the workspaces they need. The limit applies to every list, search, export, the circuits and
  the API.
- A network or circuit in another workspace answers as if it didn't exist (404), so its existence isn't revealed.
- A workspace can be made inactive: still visible for reference, but nothing in it can be changed.

**What the screens show**
- Every menu item and page shows a mark: a green key (you have access), an eye (view only) or a red lock (no access,
  with the role that's needed). Buttons for actions you can't take are shown locked, with the reason, rather than
  disappearing, so a missing permission isn't mistaken for a fault.
- These marks are for clarity. The server enforces the same rules whatever the screen shows.

---

## 9. Network access: the IP Allow List

- **The list:** approved networks as single addresses, ranges or CIDRs, each permanent or with an end date (temporary
  entries end at 11:59 PM on their last day in the organization's time zone, and the expiry is recorded, 1043).
- **Enforcement** (Organization Config): when on, every API request and every sign-in from an address outside the list
  is refused (403) and recorded (1010).
- **Per user:** enforcement applies to every user by default. An Administrator can exempt one user (for example a
  service desk account that must work from anywhere), confirmed by typing YES; never their own account, and never the
  built-in `admin`, which always needs an allowed address. Every exemption is recorded (1051) and worth an alert.
- **Lock-out protection:** enforcement can only be turned on while the list has an active entry and the Administrator's
  own address is on it. A change that would remove the access of the person making it is refused.
- **Recovery:** if everyone is locked out anyway, the server administrator can turn enforcement off with a documented
  command on the server, or with SQL scripts for each database.
- The monitoring health check and the sign-in page are never blocked, so monitoring keeps working.
- The client address is the real client behind a trusted reverse proxy (section 13). IPv4 only (IPAM manages IPv4).

---

## 10. The web application and its API

**Browser protections**
- **Content-Security-Policy:** no inline scripts, no inline styles, nothing from another site:
  `default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'`
- `X-Frame-Options: DENY` (no framing, no clickjacking), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and no caching of API responses.
- **No HTML injection:** the screens build every element from text, never from HTML, so user data can't become markup or
  script. IPAM's own documents (like this one) are rendered the same way.
- **Anti-forgery:** every change needs a custom request header that another website can't send, on top of the
  `SameSite=Strict` cookie. A request without it is refused and recorded (1012).

**The API surface**
- The browser and the API are the same application: there are no separate API keys, tokens or service accounts, so
  there are no long-lived credentials to leak. Every call carries the user's own session and is checked like a click.
- **Reachable without signing in:** only the sign-in and sign-out calls, the health check (`/api/health`, which returns
  the status, the product name and its version), and the static files of the user interface (which contain no data).
  Every other route needs a session, and an unknown route answers with a plain "not found" that reveals nothing.
- **Every route states its access**, and an automated test fails if one doesn't. Another test signs in as a read-only
  user and checks that every changing route refuses it.
- **Concurrency:** every change carries the version of the record it was based on, and is refused if someone else changed
  it in the meantime ("changed by X, reload").
- **Errors** never return stack traces to the browser. They carry a request ID, so a user's report can be traced to the
  server's log lines.
- **During maintenance** (moving the database to another server), every changing request is refused until the restart.

**Files in and out**
- **Exports** (CSV or JSON) need the Export role and the view role for what's exported, and are filtered by workspace.
  Each is recorded with what, format, filters and number of rows (6001 to 6019). Text that a spreadsheet could take for a
  formula is neutralized.
- **Imports** need the Import role and the matching administrator role. Every row is checked by the same rules as the
  screens, the whole file runs in one transaction, and a preview (dry run) changes nothing and leaves no record.
- **The company logo** accepts PNG, JPEG, GIF or WebP only, checked by the file's content, not its name; no SVG (which
  can carry script); at most 1 MB.

---

## 11. Encryption in transit and at rest

**In transit**
- **Browser to IPAM:** HTTPS, terminated at the customer's reverse proxy. The supplied nginx and Apache configurations
  allow only TLS 1.2 and 1.3 and send HSTS (`max-age=31536000`). The sign-in cookie is marked `Secure` behind HTTPS.
- **Proxy to container:** plain HTTP on the server itself. The container's port is published on `127.0.0.1` only, so
  nothing else on the network can reach it.
- **IPAM to its database:** SQLite is a local file. For PostgreSQL and SQL Server, TLS is set in the connection string
  (for example `SSL Mode=Require` or `Encrypt=True`) and enforced by the database server.
- **IPAM to the mail service:** SMTP checks the server's certificate (STARTTLS or TLS). Sending without encryption is
  possible for a trusted local relay, with a warning on the page. Microsoft 365 uses HTTPS and OAuth 2.0.

**At rest: what IPAM encrypts**
- **Mail credentials** (the SMTP password, the Microsoft 365 client secret, the proxy password) are encrypted with the
  app's Data Protection keys. A copy of the database without the keys can't read them. They're never sent back to the
  browser and never logged.
- **Passwords** aren't encrypted but hashed (PBKDF2, section 7): they can't be recovered, only checked.
- **The sign-in cookie** is encrypted and signed with the same keys.

**At rest: what IPAM does not encrypt, and what to do**

| Item | Where | Protection to apply |
|---|---|---|
| The SQLite database | `/data/ipam.db` | Encrypt the disk or volume (for example LUKS on RHEL); restrict the folder to the container's user |
| PostgreSQL or SQL Server data | The customer's database server | The database's own encryption (SQL Server TDE; PostgreSQL on an encrypted volume) |
| Backups | The backup folder, often a network share | An encrypted share or volume, restricted access (section 12) |
| Log files and archives | `/data/logs`, the archive folder | An encrypted volume; restricted access; the SIEM's own controls |
| Data Protection keys | `/data/keys` | Restrict the folder to the container's user; they protect cookies and mail credentials |
| Exported files | Wherever users save them | The organization's data-handling policy; every export is recorded |

Encrypting backups and protecting the keys inside IPAM itself are on the roadmap (section 30).

---

## 12. Backups, recovery and continuity

- **SQLite:** IPAM backs itself up on a schedule (Administration → Backup Settings, Administrators only): every N hours
  to a chosen folder, keeping the newest N copies. Each backup is a consistent copy taken while IPAM runs. Every backup,
  and every failure, is recorded (7010, 7011), and the Backups page lists them.
- **Before every upgrade** IPAM writes an extra backup (`pre-upgrade-schema-…`) and refuses to upgrade if it can't. These
  aren't deleted automatically.
- **PostgreSQL and SQL Server:** backups follow the customer's own database policy and tools.
- **A backup holds everything** in the database: the network design, circuits and costs, users and the audit history.
  Mail credentials inside it stay encrypted; the rest is readable by anyone who can read the file. Keep backups on an
  encrypted, access-controlled share, separate from the server.
- **Restore** is a documented procedure (the Deployment Guide). Test it regularly.
- **Startup safety:** IPAM refuses to start on a data folder that would be lost when the container is replaced, refuses
  to start fresh where backups exist (so an empty database can't silently replace a real one), and refuses a database
  from a newer version.

---

## 13. Hosting: the container and the server

**The container**
- Built on Microsoft's official ASP.NET Core 10 runtime image (`mcr.microsoft.com/dotnet/aspnet:10.0`).
- Runs as the non-root `app` user. All data (database, keys, logs, backups by default, logo) is in one mounted volume,
  `/data`.
- Listens on port 8080 inside the container, published on `127.0.0.1:8080` only. Users reach IPAM through the reverse
  proxy on HTTPS.
- The container console log is rotated (50 MB × 5 files) so it can't fill the disk.

**The reverse proxy** (supplied configurations for nginx and Apache)
- TLS 1.2 and 1.3, HSTS, and the real client address passed in `X-Forwarded-For`.
- IPAM trusts `X-Forwarded-For` only when told to, and only from private and loopback addresses (where the proxy is),
  not from arbitrary clients. Because the app port is published on the server only, a client can't reach it directly to
  forge that header.

**Licence keys** (Administration → License): one signed key per module, checked offline; IPAM holds only the public key, and
nothing is sent anywhere. A key holds the customer's name, the module, the Server ID, and the issue and expiry dates; no
personal data and no usage figures. The Server ID comes from an Installation ID in the database and the host's
`/etc/machine-id`, mounted read-only. A module without a valid key turns read-only and keeps its data; Lists and
Administration never lock. Licence changes and a changed Server ID are recorded (7050 to 7052).

**The server** (the customer's): RHEL with SELinux enforcing (volumes labelled `:Z`), firewalld allowing only HTTPS,
the host's time service (chrony), and host auditing (auditd, `/var/log/secure`). The Deployment Guide covers each step.

---

## 14. Secure development and the supply chain

- **Small dependency footprint.** Six third-party .NET libraries: Dapper (database mapping), Microsoft.Data.Sqlite,
  Npgsql (PostgreSQL), Microsoft.Data.SqlClient (SQL Server), MailKit (mail) and System.Security.Cryptography.Pkcs.
  The user interface is plain JavaScript with no build step and no Node.js packages; Bootstrap's CSS (5.3.8) and the
  Tabler icons are bundled, not fetched.
- **Built on supported platforms.** .NET 10 (long-term support), with security updates through Microsoft's servicing.
- **Strict builds.** Every compiler warning is an error, so code with warnings can't ship.
- **Automated tests**, run before every release: more than 650, covering the IP math at every boundary, CSV escaping and
  formula protection, password rules, and the whole application started in-process on a throwaway database. The
  application tests also run against PostgreSQL and SQL Server. Among them:
  - every API route has an access rule;
  - a read-only user is refused on every changing route, and a user with one role gets exactly that role;
  - secrets never reach the log files, the audit log or the API;
  - an unattended screen can't keep a session alive;
  - the recovery scripts work on every database.
- **Data access** uses parameterized queries throughout (no SQL built from user input).
- **Changes to the database schema** are numbered migrations, never edits to shipped ones, with an automatic backup
  before each upgrade.
- **Releases** are versioned, tagged and built by a documented release process into a container image.

An SBOM (software bill of materials) and automated dependency scanning are on the roadmap (section 30).

---

# Part C: logging and monitoring

## 15. What IPAM records

IPAM records three kinds of thing.

**Changes to data, with the values before and after.**
- Network blocks: created, deleted, moved between workspaces, split, joined.
- Subnets: allocated; details changed (name, VLAN, site, gateway, notes, lists, tags, cloud provider, type, links); sub
  blocks made or removed.
- Circuits: added, changed (including dates, costs and linked networks), deleted.
- Lists: sites, environments, divisions, products, block types, IP Use Types, circuit providers, circuit types,
  vendors (with their representatives) Product URLs (with their products, sites and public IPs) and VPN Service Purposes added, changed, made active
  or inactive, deleted; tags renamed, merged, deleted.
- Workspaces: created, changed, activated or deactivated, deleted.
- Email contacts and distribution groups.
- Changes made by imports, row by row.

**Who came in, and what they did.**
- Sign-in, failed sign-in (with the reason: unknown user, wrong password, disabled account, locked), sign-out.
- Sessions that were no longer valid: a password reset or account disabled since; an expired or unreadable sign-in; a
  session ended by a timeout, the nightly sign-out or Clear All.
- Too many sign-in attempts from one address; accounts locked and unlocked.
- Password changes, resets, expiry and reminders.
- Every screen opened, and one line for every request the browser made to the server.

**Everything a security team watches.**
- User accounts and groups: created, changed, enabled or disabled; email changes; group membership; roles given or taken
  directly; which workspaces each person can see; activity timeout overrides. Roles are built in and can't be changed,
  but who has them can, and every change is recorded.
- Access denied: someone tried an action their roles don't allow (the event names the role that was needed).
- Requests refused because they lacked IPAM's anti-forgery header (the signature of a cross-site request forgery).
- IP Allow List: entries added, changed, deleted or expired; enforcement turned on or off; per-user requirements; each
  blocked attempt.
- Sensitive views: who opened the audit log, the users, the groups, the roles, the IP Allow List, the Settings, the
  Organization Configs, the Log Settings, the Database page, the backups, the Backup Settings, the Session Timeouts.
- Searches, with what was searched for.
- Exports (what, which format, how many rows, which filters), import template downloads, and every import.
- Settings changes: session timeouts, Clear All, the Organization Time Zone and other Organization Configs, email
  settings, backup settings, the database being moved, log settings, debug logging on or off, log files deleted and audit
  entries purged by retention, log files checked for tampering.
- Backup administrator work started and ended, and each notification email sent or failed.
- IPAM starting (with its version and settings), stopping, upgrading its database, or being stopped from starting by a
  safety check; its database becoming unavailable.

Operational messages, warnings and errors (with stack traces) are recorded for the people who run the server. While an
administrator has turned it on, extra debug detail is recorded too.

---

## 16. Five log files, one audience each

IPAM writes **five log files a day**. **Every kind of event always goes to the same one of the five.** A sign-in always
goes to the access file, a site change always to the payload file, an export always to the security file. So each file
can be sent to its own SIEM index, with its own access rules and its own retention, and nothing appears twice.

The **Event IDs** tab of Log Settings shows, for every event, which file it goes to. Every line in every file carries
the user, the sign-in session and the client IP, so one search can still follow a person across all of them.

| File | Holds | Typical readers |
|---|---|---|
| `ipam-access-YYYYMMDD` | Who came in, from where, and what they touched: sign-in, sign-out, failed sign-ins, rejected and expired sessions, rate limiting, password changes, resets and expiry, every screen opened, one line per API request | Security operations: sign-in monitoring, brute-force detection, "where was this account used from" |
| `ipam-payload-YYYYMMDD` | The data itself: every record created, changed (including made active or inactive) or removed, with old and new values | Data owners, change management, the network team. **Restrict:** it describes the network design and circuit costs |
| `ipam-security-YYYYMMDD` | Privileges and controls: users, groups and access; lockouts; access denied; the security header; the IP Allow List; sensitive views and searches; exports, imports and templates; settings and session controls; the database; logging and its retention; email notifications; start, stop and upgrade | The CISO's office and the SOC: privilege abuse, data leaving, controls being changed, logging being tampered with |
| `ipam-app-YYYYMMDD` | The app's own health: operational messages, warnings, errors with stack traces, backups | Operations and support |
| `ipam-debug-YYYYMMDD` | Only while debug logging is on: each request's query string and headers (cookies and credentials removed), response sizes, timings | Whoever is troubleshooting, for a limited time |

**One file instead of five (a choice).** If your SIEM is easier to feed from one place, Log Settings → **Log file
layout** writes every line to one file a day, `ipam-all-YYYYMMDD`. Nothing else changes: each line has the same fields,
and its `log_type` (access, payload, security, app or debug) is the standard source field to filter, index, chart and
alert on. That field is on every line in both layouts. The trade-offs:
- One file means one retention period and one tamper-evidence chain for everything, and one input for the SIEM.
- Five files let you keep the security log longer than the rest, give different teams different files, or send only
  some files to the SIEM.

Choosing is a decision for your security team; the change is recorded (7030) with the layout before and after.

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
- **Files only:** screen views, per-request lines and debug detail, which are high in volume.

**The Audit log page** (the Audit Log Viewer role):
- columns Date/Time, User, Client IP, Event ID, Event Name, Event Description and Event Details, and an optional
  Browser column;
- a search box above each column, and filters for user, kind of action, date range, status and client IP;
- an export of exactly what's shown;
- a **Tamper check** tab (section 19).

Opening the audit log is itself recorded.

**User Activity** (every signed-in user) is a narrow, read-only view of the same database audit log.
- It shows changes to network blocks, circuits, lists, block types and workspaces, and imports: your own, or everyone's.
- **It never shows** sign-ins, security events, users, groups, roles, settings or the IP Allow List.
- **It never shows client IP addresses or browsers.**
- **Exports** appear only in the exporting user's own activity.
- **Each row is filtered on the server** by what the viewer may see anyway (their roles and workspaces), so it reveals
  nothing a user couldn't already open.
- It records nothing new and doesn't change the log.

---

## 17. Every line: the field dictionary

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
| 18–19 | `proxy_by`, `proxy_reason` | Proxy access: the person viewing IPAM as `user`, and the reason they gave. Blank otherwise | `kadmin`, `INC-1234` |
| 20 | `client_ip` | The address the request came from (the real client behind a trusted reverse proxy) | `198.51.100.23` |
| 21 | `proxy_chain` | `X-Forwarded-For` as received | `198.51.100.23, 10.0.0.5` |
| 22 | `user_agent` | The browser's full User-Agent | `Mozilla/5.0 …` |
| 23–24 | `browser`, `os` | Short forms | `Edge 141`, `Windows` |
| 25–26 | `http_method`, `path` | The call made, without the query string (screen views: `VIEW` and the screen) | `POST`, `/api/sites` |
| 27–28 | `http_status`, `duration_ms` | On request lines | `200`, `12` |
| 29 | `workspace` | The workspace the user was working in | `Production` |
| 30 | `action` | The action code | `site.update` |
| 31–32 | `entity_type`, `entity_id` | What it was about | `site`, `7` |
| 33–34 | `old_values`, `new_values` | Before and after (JSON objects in JSON files) | `{"city":"Seattle"}` |
| 35 | `error_message` | For errors: the exception and stack trace | |
| 36 | `audit_id` | The entry's ID in IPAM's database | `4182` |
| 37 | `category` | For operational messages: where in IPAM they came from | |
| 38–39 | `prev_hash`, `hash` | The tamper-evidence chain (section 19) | 64 hex characters each |

**What can't be captured, and why.**
- **A browser's own private (LAN) IP address.** Browsers don't reveal it, and the old trick that exposed it has been
  closed by browser makers for privacy reasons. The client IP is the address IPAM sees, after any trusted proxy.
- **Location from an IP address (country, city).** It needs an outside database that has to be kept current; the SIEM is
  the better place for it.

---

## 18. Event IDs and suggested alerts

IPAM's catalog has **227 events**. Every event has a permanent number, grouped by area like Windows event IDs. An ID is
never reused or renumbered; new events get new numbers.

| Range | Area | Examples | File |
|---|---|---|---|
| 1001–1007, 1031–1032 | Sign-in and sessions | 1001 Signed in · 1002 Sign-in failed · 1003 Signed out · 1004 Session rejected · 1005 Too many sign-in attempts · 1006 Password changed · 1007 Password reset · 1031 Page viewed · 1032 Session expired | access |
| 1008, 1009, 1015–1019 | Lockout, backup administrator work and proxy access | 1008 Account locked · 1009 Account unlocked · 1015 Backup administrator work started · 1016 Backup administrator work ended · 1017 Proxy access started · 1018 Proxy access ended · 1019 Change refused while viewing as a user | security |
| 1013, 1014 | Password expiry | 1013 Password expired · 1014 Password expires soon | access |
| 1010–1051 | Security controls | 1010 Blocked by the IP Allow List · 1011 Access denied · 1012 Request without the security header · 1020–1029, 1033–1034 Sensitive views · 1030 Search · 1040–1043 IP Allow List changes · 1050 Organization Config changed · 1051 Allowed-IP requirement changed | security |
| 2000s | Users, groups and access | 2001 User created · 2002 User changed · 2003 User's groups changed · 2004 User's workspaces changed · 2005 User's time zone set · 2006 User's email changed · 2007 Role given to a user · 2008 Role taken from a user · 2009 Activity timeout override changed · 2101–2106 Groups | security |
| 3000s | Network blocks, subnets, circuits, whitelisting requests, VPNs and Service IP Mappings | 3001 Network block created · 3010 Network split · 3013 Network details changed · 3020 Sub block created · 3030–3032 Circuit added, changed, deleted · 3050–3052 Whitelisting request added, changed, deleted · 3060–3062 VPN added, changed, deleted · 3070–3072 Service IP Mapping added, changed, deleted · 3040 Linked IPs made typed (their network was deleted) | payload |
| 4000s | Lists | 4001–4003 Sites · 4011–4013 Environments · 4021–4023 Divisions · 4031–4033 Products · 4041–4043 Block types · 4051–4053 IP Use Types · 4061–4063 Circuit providers · 4071–4073 Circuit types · 4081–4083 Vendors · 4091–4093 Tag renamed, merged, deleted · 4101–4103 Product URLs · 4111–4113 VPN Service Purposes | payload |
| 5000s | Workspaces | 5001–5003 Workspace created, changed, deleted (payload) · 5004–5005 Workspace members (security) | payload / security |
| 6000s | Export and import | 6001–6024 Exports · 6050 Template downloaded · 6101–6121 Imports | security |
| 7000s | Settings, sessions, database, backups, logging | 7001 Setting changed · 7003 Session timeouts changed · 7004 All sessions ended · 7020–7024 Database moved or copied · 7030 Log settings changed · 7031/7032 Debug on/off · 7033 Old log files deleted · 7034 Old audit entries purged · 7035 Log write failed · 7036 Log files checked · 7037 Log tampering found · 7038 Log files compressed · 7039 Log files archived · 7041 Log archiving failed · 7042 Old audit entries archived · 7043 Logging degraded · 7044 Logging restored · 7050/7051 Licence key added/removed · 7052 Server ID changed · 7060 Registry lookup settings changed · 7010/7011 Backups (app) · 7002 Logo and 7040 Reference data (payload) | security, app, payload |
| 8000s | Email and notifications | 8001 Email settings changed · 8002 Test email sent · 8003 Test email failed · 8010 Notification emailed · 8011 Notification email failed · 8104 Email contact made a user (security); 8101–8103 Email contacts, 8111–8113 Distribution groups (payload) | security, payload |
| 9000s | System | 9001 IPAM started · 9002 IPAM stopped · 9003 Database upgraded · 9004 Startup blocked · 9005 Database unavailable (security) · 9101 API request (access) · 9102 App message · 9500 Unexpected error (app) · 9900 Debug detail (debug) | as shown |

Each area has an "other" event (x999) for anything without its own ID. The complete, current list, with each event's
description and file, is on **Administration → Log Settings → Event IDs**, and exports as CSV or JSON for building
alerts.

**Suggested alerts**

| Watch for | Why |
|---|---|
| 1002 more than 5 times in 10 minutes for one user or one client IP | Password guessing |
| Any 1005 | Automated guessing, already being slowed down |
| Any 1008, especially for the built-in `admin` | An account locked by repeated wrong passwords |
| Any 1015 | A Backup Administrator is working on other Administrators' accounts |
| Any 1017 | Someone is viewing IPAM as another user (the reason is in the details); 1019 shows they tried to change something |
| Any 8011 | A security notification email didn't go out |
| 2007 with `admin` or `admin.backup` | A powerful role given to a user directly |
| Any 2009 | A user's sign-in can now last longer than the organization's maximum |
| Any 7004 | Everyone was signed out: expected only during an incident or a planned change |
| Any 1010, 1011 or 1012 | Someone outside their access, outside the allowed networks, or a forged request |
| 1050, 1040–1043 | The IP Allow List, its enforcement or another Organization Config changed |
| Any 1051 | A user was exempted from the IP Allow List (or the exemption removed) |
| 7003 | The session limits were changed (check old and new values) |
| 2003, 2105, 2106 involving the Administrators group | Privilege change |
| 2006 not expected from the user's administrators | Someone changing the address an account signs in with |
| 6008 (users exported), 6011 (audit log exported), 6019 (circuits exported), or an unusual number of exports by one user | Sensitive data leaving |
| 1030 in bulk from one session | Someone mapping the network through search |
| 7030, 7031, 7034 outside the daily clean-up | Logging changed, or history removed |
| Any 7035, 7037, 7041 or 7043 | Logging failed or degraded, log files were changed, or archiving failed |
| Any 7052 | The Server ID changed: the server was moved, rebuilt or cloned (expected only for a planned move) |
| Any 9005 | IPAM couldn't use its database (also look at the database server's own logs, section 21) |
| A gap between 9002 and the next 9001 | IPAM was down; nothing was logged in between |
| Any 9004 or 9500 | A blocked start, or an unexpected error |

---

## 19. Tamper evidence

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
- **Before compressing or archiving** a file, its chain is checked too (section 20).

**What it does and doesn't do.** The chain shows that a file was altered; it can't stop someone with full control of the
server from altering it. The protection against that is to ship the files to the SIEM as they're written, so a copy
exists outside the server, and to keep the database audit log, a second, independent record of every change and
sign-in. Both are part of the recommended deployment.

---

## 20. Retention, compression and long-term archiving

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
SIEM, or both. Legal holds: raise "keep for" (or turn Archive on) before the holding period would end; every change to
retention is recorded.

---

## 21. The database audit log, and the database server's own logs

**IPAM's database audit log** is a table in IPAM's own database: the history shown on the Audit log page (changes,
sign-ins and security events). It is IPAM's record, not the database server's.
- **It reaches the enterprise logging system already.** Every entry is copied, within about a second of being saved, to
  the access, payload or security log file, which the SIEM collects. The files are the extract; the database copy is a
  second, independent record.
- **Entries are kept 366 days by default** (30 to 3,650), and can be archived before they're purged (section 20).

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
  write its data; it needs no server-wide rights. The Deployment Guide gives the minimum grants.

---

## 22. Logs around IPAM: the server, the container, the proxy

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
| The database server | section 21 | Database logins and direct changes |
| IPAM's startup log | `/data/logs/startup-YYYYMMDD.log` | Bootstrap diagnostics written even if everything else fails (also on the console) |

---

## 23. Bringing the logs into a SIEM

The files are written to the log folder: `/data/logs` inside the container, `/opt/ipam/data/logs` on the host with the
standard deployment, unless an administrator chose another folder. They're append-only and can be read while IPAM
writes them, which is what forwarders expect. The SOC needs read access to that folder (or the container console), not
an IPAM account.

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
roadmap (section 30).

---

## 24. Investigations: what a security team can answer

| Question | Where to look |
|---|---|
| Who signed in as this user, from where, and with which browser? | access: 1001 with `user`, `client_ip`, `browser`, `os`, `session_id` |
| Has someone been guessing passwords? | access: 1002 and 1005 by `client_ip` and `user`; security: 1008 |
| What did this person do in that session? | Every file: filter on `session_id`. Screens (1031), calls (9101), changes (payload), sensitive views, searches, exports (security) |
| Who changed this subnet or circuit, when, and what was it before? | payload: `entity_id`, with `old_values` → `new_values`. Or the Audit log page, "Change history" on the record |
| Who changed a circuit's cost or contract dates? | payload: 3031 with `old_values` → `new_values` |
| Who gave this person administrator rights? | security: 2003 and 2105 on the Administrators group; 2007 for a role given directly |
| Did anyone take data out of IPAM? | security: 6001–6024 (what, format, filters, rows), by `user` |
| Has someone been mapping the network? | security: 1030 (searches with their terms) and access: 9101 by `session_id` |
| Did anyone try something they weren't allowed to? | security: 1011 (with the role needed), 1012, 1010 |
| Who changed the IP Allow List, or turned enforcement off? | security: 1040–1043, 1050, 1051 |
| Who changed the session limits, ended all sessions, or gave a user a longer session? | security: 7003, 7004, 2009 |
| Did anyone look at the audit log or the users? | security: 1020, 1021 |
| Was logging changed, turned down or tampered with? | security: 7030, 7031/7032, 7033/7034, 7035, 7037, and a gap between 9002 and 9001 |
| Did the error this user reported happen, and why? | The request ID on their screen → app (9500, with the stack trace) and access (9101) |

---

## 25. Protecting the logs, and what is never logged

**Never logged.**
- Passwords: sign-in, change, reset, temporary passwords for new users.
- Password hashes and the security stamps that invalidate sessions.
- Sign-in cookies and the `Authorization` header (removed from the debug lines too).
- Database connection strings and their passwords.
- Mail credentials: the SMTP password, the Microsoft 365 client secret and the proxy password. The audit log records only
  whether each is set, replaced or removed.

An automated test signs in, creates users with temporary and permanent passwords and fails a sign-in on purpose, then
checks every log file for those strings. A second test does the same for database server passwords used on the
Database page, and a third for the mail credentials in the API, the audit log and the log files. API request lines
record the path without its query string; only debug lines, while debug logging is on, include the query string.

**Personal data in the logs.** Usernames, display names, client IP addresses and browser details are personal data in
many jurisdictions. They're recorded because an investigation needs them. Retention limits (section 20) and per-file
access in the SIEM let the organization keep them only as long, and only for the people, it needs (section 26).

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

# Part D: privacy, governance and assurance

## 26. Privacy and personal data

**Roles.** The customer is the controller of all personal data in IPAM, and processes it on its own systems. The maker
of IPAM receives none of it and is not a processor (section 4).

**What personal data IPAM holds, and why**

| Data | About whom | Purpose | Kept |
|---|---|---|---|
| Email, first and last name, display name, username, time zone, groups and roles | IPAM users | Accounts, access control, showing who did what | While the account exists (deactivated accounts stay, so history keeps its meaning) |
| Password hash and history, lockout counters | IPAM users | Authentication and its rules | While the account exists |
| Sign-in history, client IP address, browser and operating system | IPAM users | Security monitoring and investigations | Per the log and audit retention (section 20; default 366 days) |
| Names in the change history ("changed by") | IPAM users | Accountability for changes to the network plan | Per the audit retention |
| Proxy access sessions: who viewed IPAM as whom, when, and the reason | IPAM users | Troubleshooting a user's problem, with accountability; telling the user it happened | While the accounts exist; the matching log lines per the log retention |
| Name, phone and email of vendor representatives | Third parties | Contacting suppliers about circuits | Until removed by a user |
| Name and email of customer contacts on whitelisting requests | Third parties (customers' staff) | Telling customers when a whitelisted public IP changes | Until the request is changed or deleted by a user |
| Name and email of the Side A contact on VPN Services | Third parties (customers' and partners' staff) | Reaching the other side of a VPN about changes and outages | Until the VPN is changed or deleted by a user |
| Name and email of email contacts and distribution groups | Staff and third parties | Sending IPAM's notifications | Until removed by a user |
| Free text in notes and descriptions | Possibly anyone | The organization's own records | Until changed; advise users not to put personal data in notes |

**Principles**
- **Minimization:** IPAM asks only for what it uses. It doesn't track location, doesn't use cookies beyond the sign-in
  cookie (no analytics, no advertising, no third parties), and doesn't profile users.
- **Storage limitation:** retention is set per log file and for the audit log, and every purge is recorded.
- **Limited access:** personal data in the logs is in the access and security files, so the SIEM can restrict who reads
  them. User Activity, the one view every user has, never shows IP addresses or browsers.
- **Transparency:** each user sees their own sign-ins and access on My Account, and every time someone viewed IPAM as
  them (proxy access), with the reason; they're also told at their next sign-in.
- **Security of processing:** Part B.

**Requests from individuals**
- **Access and portability:** the users list, the audit log (filtered on the person) and the vendor and contact lists
  export as CSV or JSON.
- **Rectification:** names and emails can be corrected on the Users page (an email change is recorded, 2006).
- **Erasure:** today a user is deactivated, not deleted, and their name stays in the audit history and the log files
  until retention removes it, because the audit trail's integrity is a security control (and often a legal duty).
  Vendor representatives and email contacts can be deleted. A supported way to anonymize a departed user's details is
  on the roadmap (section 30).

The organization's privacy notice to staff should mention that IPAM records sign-ins (with IP address and browser) and
changes, for security and accountability.

---

## 27. Incident response and recovery

| Situation | What to do in IPAM | Recorded |
|---|---|---|
| A password or session may be stolen | Reset the user's password (ends their sessions at once), or deactivate the account | 1007, 2002 |
| Many accounts may be affected | **Clear All Session Tokens** on Session Timeouts: everyone signs in again | 7004 |
| Access from an unexpected network | Turn on IP Allow List enforcement, and remove any exemptions users don't need | 1050, 1051 |
| Someone has more access than they should | Remove them from groups or take roles away; it applies at their next click | 2003, 2008 |
| Data may have left | Search the security log for exports (6001–6024) and searches (1030) by user and session | — |
| Logs may have been altered | Audit log → Tamper check, or `verify-logs` on the server; compare with the SIEM copy | 7036, 7037 |
| Locked out by the IP Allow List | The server administrator runs the documented `allowlist` recovery command or SQL script | on the server |
| An Administrator is locked out | Another Administrator unlocks them, or a Backup Administrator; on the server, `reset-password` | 1009, 1015 |
| The built-in `admin` is locked out | Contact support for the database unlock procedure | 1009 |
| Data was changed wrongly | The change history shows the old values; restore from backup if needed (section 12) | — |
| Evidence is needed | Export the audit log for the period, and keep the original log files (archive or SIEM) | 6011 |

---

## 28. Shared responsibility: IPAM and the customer

| Area | IPAM provides | The customer provides |
|---|---|---|
| Identity | Accounts, password rules, lockout, session limits | Joiner, mover and leaver processes; periodic access reviews (Users and Groups pages, exports) |
| Access | Roles, groups, workspaces, guard rails, IP Allow List | Deciding who gets which role; keeping Administrators few |
| Network | An app port published on the server only; supplied proxy configurations | The reverse proxy and its certificate; firewalld; network segmentation |
| Encryption | TLS settings in the supplied proxy configurations; encrypted mail credentials; hashed passwords | TLS certificates; disk, database and backup encryption |
| Hosting | A non-root container on Microsoft's base image; startup safety checks | The server, its patching, SELinux, time service, host auditing |
| Updates | Versioned releases on supported .NET | Applying IPAM releases and base-image updates |
| Backups | Scheduled SQLite backups; a backup before every upgrade | Where backups go, their protection, restore tests; backups of PostgreSQL or SQL Server |
| Logging | The audit log, five SIEM-ready files, tamper evidence, retention, health status | Collecting the logs into a SIEM, alerts, and their retention there |
| Monitoring | `/api/health`; the Logging status bar; events for every failure | Watching them |
| Privacy | Minimization, retention settings, per-file access, exports for requests | The privacy notice, lawful basis, answering requests |

---

## 29. How the design supports common frameworks

IPAM is software, not an organization, so it can't itself be certified against a standard. Compliance comes from how a
customer deploys and runs it. The table shows which requirements IPAM's design helps a customer meet. The references are
to the controls as commonly cited; your assessor's reading of your scope is what counts.

| Framework | Requirement (summary) | How IPAM helps |
|---|---|---|
| **NIST SP 800-53 Rev. 5** | AC-2 Account management | Every account, group and access change recorded; deactivation ends sessions at once |
| | AC-3 Access enforcement | Every API route checked on the server; an automated test for every route |
| | AC-6 Least privilege | 37 single-purpose roles, view and edit separate, workspaces, guard rails on administrator rights |
| | AC-7 Unsuccessful logon attempts | Lockout after 5 wrong passwords for 15 minutes (configurable), rate limiting, recorded (1002, 1005, 1008, 1009) |
| | AC-11 Device lock | A warning two minutes before the idle timeout; the sign-in ends at the timeout |
| | AC-12 Session termination | Idle timeout, maximum length, nightly sign-out, Clear All; all enforced by the server |
| | AC-17 Remote access | The IP Allow List; HTTPS only through the proxy |
| | AU-2, AU-3, AU-12 Event logging, content, generation | The event catalog; who, what, when, where, source and outcome on every line; generated by the server |
| | AU-6 Review, analysis and reporting | The Audit log page, SIEM-ready files, event IDs and suggested alerts |
| | AU-8 Time stamps | UTC with milliseconds everywhere |
| | AU-9 Protection of audit information | Hash chain, tamper check, Administrators only for logging, secrets never logged |
| | AU-11 Audit record retention | Per-file retention up to 3,650 days, compression, archive, every purge logged |
| | CM-6 Configuration settings | Every setting change recorded with old and new values |
| | CP-9 System backup | Scheduled backups, a backup before every upgrade |
| | IA-2, IA-5 Identification and authenticators | Individual accounts; password rules, expiry, history; PBKDF2 hashing |
| | SC-8 Transmission confidentiality | TLS 1.2/1.3 and HSTS at the proxy |
| | SC-28 Protection of information at rest | Mail credentials encrypted, passwords hashed; disk and database encryption by the customer |
| | SI-10 Input validation | Every field checked on the server; imports by the same rules; formula-safe CSV |
| | SR-3, SR-4 Supply chain | Six libraries, bundled front end, no runtime downloads; SBOM on the roadmap |
| **ISO/IEC 27001:2022, Annex A** | 5.15, 5.18, 8.2, 8.3 Access control, access rights, privileged access, restriction | Roles and groups, workspaces, guard rails, every change recorded |
| | 5.34 Privacy and protection of PII | Section 26 |
| | 8.5 Secure authentication | PBKDF2, password rules, lockout, generic errors, rate limiting, secure cookie, session limits |
| | 8.13 Information backup | Scheduled and pre-upgrade backups |
| | 8.15, 8.16, 8.17 Logging, monitoring, clock synchronization | Five log files, tamper evidence, retention, event IDs and alerts, UTC |
| | 8.24 Use of cryptography | TLS, PBKDF2-SHA256, Data Protection for secrets, SHA-256 log chain |
| | 8.25–8.28 Secure development and coding | Deny by default, tests for access and secrets, warnings as errors, parameterized queries |
| **SOC 2 (Trust Services Criteria)** | CC6.1–CC6.3 Logical access | Role-based access, least privilege, immediate effect of revocation |
| | CC6.6 Boundary protection | IP Allow List, the app port on the server only |
| | CC6.7 Transmission | TLS at the proxy |
| | CC7.2, CC7.3 Monitoring and evaluating events | Security events, SIEM files, statuses (FAILED, DENIED), investigation fields |
| | CC8.1 Change management | Every data and setting change recorded with old and new values |
| **PCI DSS v4.0** (if IPAM is in scope) | 8.2.8 Re-authenticate after 15 minutes idle | Set the idle timeout to 15 minutes (5 or more allowed; default 30) |
| | 8.3.4 Lock out after repeated failures | Locked after 5 wrong passwords (up to 10 allowed) for 15 minutes (at least 30 required: set Organization Config 007 to 30) |
| | 8.3.6, 8.3.7, 8.3.9 Password length, history, change | 12+ characters, last 5 not reused, 90-day expiry |
| | 10.2 Audit logs capture user activity | Sign-ins, access to audit trails (1020), invalid access (1011, 1002), changes to authentication (2000s, 1006–1007), changes to logging (7030–7034) |
| | 10.3, 10.4, 10.5, 10.6 Protect, review, retain, time | Hash chain and separated access; Audit log page and alerts; a year by default; UTC from a synchronized host |
| **CIS Controls v8** | 5, 6 Account and access management | Individual accounts, roles, deactivation, access reviews by export |
| | 8.2, 8.5, 8.9, 8.10 Audit logs | Detailed fields, SIEM-ready files, retention settings |
| **HIPAA Security Rule** (if in scope) | §164.312(b) Audit controls; (d) authentication; (a)(2)(iii) automatic logoff | Recorded activity; individual accounts; session timeouts |
| **GDPR / privacy laws** | Art. 5 minimization and storage limitation; Art. 25 data protection by design; Art. 32 security | Section 26; retention limits; no telemetry or third parties; Part B |
| | Art. 30 records of processing | Section 26's table is a starting point for the customer's record |

---

## 30. Known limits and the roadmap

We'd rather a reviewer hear these from us.

| Area | Today | Planned or recommended |
|---|---|---|
| Single sign-on and MFA | IPAM's own accounts and passwords, with strong password rules and lockout | Single sign-on, likely Microsoft Entra ID, which brings the organization's MFA and conditional access (planned) |
| Database, backups and logs at rest | Not encrypted by IPAM; mail credentials are | Encrypted backups (planned); meanwhile disk, database and share encryption (section 11) |
| Data Protection keys | In the data folder, protected by file permissions | Protecting the key ring with a certificate or key vault (planned) |
| Security headers | CSP, framing, sniffing and referrer headers from the app; HSTS from the reverse proxy | HSTS, Permissions-Policy and cross-origin headers from the app itself (planned) |
| Supply chain evidence | Six libraries, bundled front end, supported .NET | An SBOM and dependency scanning for every release (planned) |
| Rate limiting | Sign-in, 10 a minute per address | Limits for the rest of the API, stricter for search and export (planned) |
| Erasure requests | Users are deactivated; names stay in history until retention removes them | Anonymizing a departed user's details while keeping the audit trail intact (planned) |
| Sending logs to a SIEM | Files and console, collected by the customer's agent | Direct sending to syslog over TLS, Splunk HEC and the Datadog API (planned) |
| Immutable storage | Tamper-evident (the chain shows changes); not tamper-proof on the server itself | Ship to the SIEM as written; use WORM or immutable storage there |
| Screen views | Reported by the browser; a determined user could block them | The API request lines are the authoritative record of what was fetched |
| Health check | Answers without sign-in with status, product name and version | Restrict it at the proxy to the monitoring system if the version shouldn't be visible |
| Time source | The server's clock | Run a time service on the host (chrony on RHEL), pointed at the organization's time servers |
| IPv6 | IPAM manages IPv4; the IP Allow List is IPv4 | IPv6 is on the longer-term roadmap |

---

## 31. Questions reviewers ask

**Does IPAM send any of our data to its maker, or anywhere else?**
- No. There is no telemetry, usage reporting, licence check or remote support channel. The only outbound connections are
  to the mail service you configure and, if turned on, registry lookups that send public network addresses only
  (section 4).

**Where is our data, and who can reach it?**
- On your server and in your database, in the location you choose. Only people with an IPAM account, the right role and
  workspace, from an allowed network if you turn that on, and the people who administer the server.

**Can the maker access our IPAM?**
- No. There is no built-in remote access, back door or master password. Support works only with what you choose to
  share.

**Is our data encrypted?**
- In transit, yes, with TLS at the reverse proxy. At rest, mail credentials are encrypted and passwords are hashed; the
  database, backups and logs depend on your disk or database encryption (section 11).

**Can an administrator delete audit history without it showing?**
- Not without leaving a trace. Retention purges are recorded (7034), and changing the retention is recorded (7030).
- The files are tamper-evident, and their copies in the SIEM are outside IPAM's reach.
- Someone with direct access to the server's database or file system works outside the application. The hash chain
  and the SIEM copy are the controls against that.

**Can logging be turned off?**
- Audit, access, payload and security events, no. The app log and the per-request lines can be reduced; errors are
  always written. Every change to logging is itself recorded.

**Is debug logging a risk?**
- It's off by default and only Administrators can turn it on. It writes to separate files, strips cookies and
  credentials, and runs at most 7 days before turning itself off. Turning it on and off is recorded.

**How long does a sign-in last, and can a forgotten open screen stay signed in?**
- By default 30 minutes without activity, 12 hours at most, and never past 23:59:59 in your time zone. Administrators set
  these on Session Timeouts, and the server enforces them on every request.
- An open screen doesn't stay signed in by itself: it sends nothing in the background, and the one session check at the
  end of the countdown isn't counted as activity (an automated test checks this).
- An Administrator can give one user a longer idle timeout (up to 12 hours, with no maximum); it's recorded (2009) and
  worth an alert.

**How fast does removing someone's access take effect?**
- At their next request. Roles and account status are read on every request; deactivating or resetting a password ends
  their sessions at once, and Clear All ends everyone's.

**Can a user see networks or circuits outside their workspaces?**
- No. Lists, searches, exports and the API are all filtered, and a record in another workspace answers as if it didn't
  exist.

**What stops someone exporting everything?**
- Exports need the Export role and the view role for the data, are limited to the user's workspaces, and are each
  recorded with the row count. Alert on unusual exports (section 18). Broader API rate limits are planned.

**Where do the database server's own login events go?** To the database server's audit log, not IPAM's: IPAM never
sees a login to PostgreSQL or SQL Server. Section 21 lists what to turn on. IPAM records when it can't use its database
(9005).

**How long can logs be kept?** Up to 3,650 days on disk per file, compressed after a chosen age, and moved to long-term
storage after that if wanted (section 20). There's no technical limit beyond disk space.

**How quickly do events reach the files?** Immediately for access, app and debug lines. Database-recorded events within
about a second of being saved.

**Are timestamps in local time?** No: UTC, with milliseconds, everywhere: files, console, database. (The organization's
time zone is used only for the nightly sign-out and for when temporary IP Allow List entries end.)

**What if the disk fills up?** Writes fail safely: IPAM keeps running, the failure goes to the console and startup log,
and a "log write failed" event is recorded once space is available. Before that, the Logging status bar turns red
when the disk drops under 1 GB or 5% free, and "Logging degraded" (7043) is recorded.

**Can our SOC see the events without access to IPAM?** Yes. The files and console are designed for collection. The SOC
needs read access to the log folder, or the container's console, not an IPAM account.

**Can we delete a person's data on request?** Vendor representatives and contacts, yes. Users are deactivated, and their
names stay in the audit history until retention removes them (section 26); a supported anonymization is planned.

**Where do I find the full list of events?** Administration → Log Settings → Event IDs (exportable), and the logging
reference (`docs/LOGGING.md`) in the product documentation, which also has the field reference and collector set-ups.

---

*IPAM's documentation also includes the User Guide (every screen), the Deployment Guide (installation, reverse proxy,
backups, upgrades) and the logging reference (`docs/LOGGING.md`).*
