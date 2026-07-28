# Troubleshooting

What to do when a secure change breaks an application or the standards appear to conflict.

## The hardening broke a legacy app

Do not revert the control globally. Write down:

1. What changed: identity, protocol, GPO, registry, ACL, audit policy, or application setting.
2. What broke: exact error, host, account, protocol, and timestamp.
3. What the app actually requires, not what its vendor guide says it requires.
4. Which hosts, users, and resources need the compatibility path.
5. An owner, expiry date, compensating control, and removal test for the exception.

Then scope the exception to the smallest unit that still works:

- One OU or security group, not the domain
- One service account or app pool, not every service
- One SPN or back-end resource, not unconstrained delegation
- One firewall source range, not `0.0.0.0/0`
- One legacy SMB client, not a fleet-wide signing disable

Keep the stronger control on all unaffected systems. Put the exception in the baseline diff so drift
detection reports it. A temporary exception without an owner is a permanent bypass.

## gMSA service will not start

Check in this order:

```powershell
Test-ADServiceAccount -Identity 'svc_acmeweb'
Get-ADServiceAccount 'svc_acmeweb' -Properties PrincipalsAllowedToRetrieveManagedPassword
Get-ADComputer 'WEB01' -Properties memberOf
```

Common causes:

- The host is not in the gMSA retrieval policy.
- `Install-ADServiceAccount` was not run on this host.
- AD or KDS replication has not completed.
- `Log on as a service` was not granted to `CONTOSO\svc_acmeweb$`.
- The service definition uses the account without the trailing `$` or supplies a non-empty password.
- The service needs an SPN but it was never registered.

Do not solve this by granting the gMSA Domain Admins. Fix the missing prerequisite and rerun the
account test.

## `Test-ADServiceAccount` is false after a DC change

Run the test from the actual member server, not a domain controller. Confirm the server can locate a
writable DC, the account exists in the expected domain, and the host is in the allowed principals.
If the account was created with an effective time that has not arrived, wait for it rather than
creating a second account with a weaker configuration.

## Credential Guard breaks authentication

Microsoft documents incompatibilities with Kerberos DES, RC4, unconstrained delegation, TGT
extraction, and NTLMv1. Digest, CredSSP, credential delegation, and MS-CHAPv2 can also expose
credentials or require application changes.

Identify which protocol the app negotiated. Do not immediately disable Credential Guard on every
server. Replace the protocol or delegation model first. If the app cannot be changed, isolate the
legacy host in its own OU, restrict inbound management, remove tier-0 credentials from it, record
the exception, and set a retirement date.

Credential Guard is not recommended on domain controllers and is unsupported on Exchange Server.
That is a placement decision, not a reason to disable it on member servers.

## Protected Users caused a lockout

Remove the account from the group through a break-glass path, then check:

- The domain functional level meets the requirement.
- The account has an AES key. Reset the password if it was migrated from an old domain or last set
  by an old DC.
- The account is not a service or computer account.
- The account does not need NTLM, DES/RC4, delegation, CredSSP, or offline sign-in.

Pilot with a non-tier-0 account first. Microsoft warns that the restrictions are non-configurable and
that adding highly privileged accounts without testing can lock them out.

## LSA protection prevents a plug-in from loading

Read `Applications and Services Logs\Microsoft\Windows\CodeIntegrity\Operational` for the audit
and enforcement events. Microsoft documents 3065/3066 in audit mode and 3033/3063 when enforced.

Obtain a signed update for the plug-in or driver. Do not turn off LSA protection across the estate.
If a vendor cannot produce one, isolate the workload and record the exception. With UEFI lock, a
registry edit cannot disable the setting; use the documented opt-out procedure and an out-of-band
recovery path.

## RDP Remote Credential Guard fails

Remote Credential Guard requires Kerberos. It does not fall back to NTLM, works only for direct RDP
to an AD-joined host, and does not work through Connection Broker or RD Gateway. It is not supported
by the RDP UWP app.

Check that:

- The client can contact a domain controller.
- The target has a valid name and SPN; do not use an IP address.
- The remote host allows delegation of nonexportable credentials.
- The user has Remote Desktop Users access (or the required administrator access for the mode).
- The client policy is not enforcing a different mode.

Use Restricted Admin for helpdesk support when the client may itself be compromised. A failed
Remote Credential Guard connection is not a reason to return to password-bearing RDP.

## SMB signing breaks a partner appliance

Before changing the requirement, identify the peer and confirm whether it supports SMB2/3 signing.
Use the SMB client and server audit settings to produce the documented audit events. Do not set
`EnableSecuritySignature`; it is ignored for SMB2 and later.

Scope the exception to the appliance's source and share if the business must keep it. Prefer an
upgrade or replacement. Require signing for every other client and put the exception in the baseline
and its expiry register.

## RBCD migration broke the back end

Check the resource object's `PrincipalsAllowedToDelegateToAccount` and the front-end identity. The
resource must name the exact front end, and the requested service must have the correct SPN. Confirm
that the old unconstrained or constrained setting is removed only after the new path succeeds.

Remember that RBCD makes the resource object's write ACL security-critical. A delegated operator who
can edit the computer object can change the trust.

## WinRM HTTPS will not connect

Check the certificate subject/SAN, EKU, expiration, private-key access for the WinRM service, and
firewall scope. Confirm the listener on the live host, not only the script that created it.

If the certificate cannot be fixed immediately, restrict the HTTP listener to the management VLAN and
bastion as a time-bounded exception. Do not expose it to the whole network or silently turn off
certificate validation.

## The service fails after ACL hardening

Read the service account's file, registry, certificate-store, temp, and event-log access needs. Add
one narrowly scoped data directory rather than granting Modify to the code root. Preserve
administrator and SYSTEM ownership of the binary and configuration.

For IIS, grant `IIS AppPool\<PoolName>` access to the application content only as Read/Execute, and
Modify only to an upload or Data Protection key directory. Restart and exercise the app under its real
identity. `Get-Acl` on a source tree does not prove inherited access on the target host.

## ASP.NET Core nodes log users out intermittently

A per-machine Data Protection key ring is the usual cause. Persist keys to a shared store, encrypt
at rest, restrict the share to the app identity, and set the same `SetApplicationName` on every node
of the same app. Give different applications different names.

Do not turn off cookie validation or antiforgery checks. That masks the symptom by removing the
control that caught the key-ring split.

## The client still sees a stack trace

Check all layers: ASP.NET Framework `customErrors`, ASP.NET Core `UseDeveloperExceptionPage`, IIS
custom errors, and the reverse proxy's error response. Test from a remote client through the real
binding, not only localhost. Log the exception server-side with a correlation ID and return a generic
error.

A code review cannot prove the production environment variable is not `Development`. Mark that
runtime fact unknown until checked on the host.

## Audit events are missing

Run:

```powershell
auditpol.exe /get /category:*
gpresult.exe /h C:\Temp\rsop.html /f
```

Check that the subcategory is enabled, that basic audit policy is not overwriting it, and that the
Security log has enough size and retention. For 4688, both Audit Process Creation and Include command
line in process creation events are required. Check the event channel and forwarding agent next.

Do not mark a GPO backup pass. It describes intended policy, not effective policy.

## An event fires too often

Do not disable the subcategory first. Filter at the collector:

- 4672: suppress expected SYSTEM, Local Service, and Network Service logons; alert on unusual
  subjects or privilege lists
- 4624/4625: scope to tier-0 accounts, service accounts, and unexpected source hosts
- 4728/4732/4756: alert on additions to protected groups, not every ordinary group
- 4697: alert on unexpected paths and non-built-in service accounts

Retain the raw event. A noisy rule needs a better predicate, not a blind spot.

## Two standards seem to disagree

The Top 10 is a risk taxonomy; ASVS is a verification set. Use the ASVS chapter to choose what to
check and the Top 10 category to report why it matters. CIS and SCT baselines are starting points,
not permissions to ignore application requirements. Use the more secure option unless a documented
compatibility constraint says otherwise, then record the exception as above.
