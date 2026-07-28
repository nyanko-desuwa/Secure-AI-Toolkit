# Common Mistakes

Failures seen repeatedly in Windows hardening reviews. Each entry says what it looks like, why it
fails, and what holds.

## Domain Admin is a service-account migration target

```text
sc.exe query AcmeSync
SERVICE_START_NAME: CONTOSO\svc_admin
```

The team calls it "a service account" and stops asking questions. If that principal is in Domain
Admins, the service process is a tier-0 credential cache on a tier-1 host. RCE in the application or
a local admin on the server becomes a domain compromise path.

Fix: virtual account if no domain resource is needed; gMSA if it is. Grant the resource access to
the new identity, then remove the domain user from every privileged group.

Why it holds: no human password, automatic rotation, and a retrieval ACL on the gMSA. A long password
on the old account does not remove LSASS exposure.

## Giving every user local admin for one application

The application writes its cache beside its executable, so someone adds all users to Administrators.
That turns a file-permission bug into arbitrary code as SYSTEM.

Fix: create `C:\ProgramData\Acme\state`, grant the app identity Modify there, keep
`C:\Program Files\Acme` administrator/SYSTEM-owned and read-only to the app.

Why it holds: the app has the write it needs and no token that can rewrite services, drivers, or
other users' files. A user-writable program directory would be the wrong fix in a different form.

## Assuming UAC makes an administrator safe

UAC is a consent and token-separation mechanism. An administrator who always approves elevation,
or an interactive session configured to run elevated, has defeated the security boundary in practice.
UAC is not a privilege-reduction strategy for services.

Fix: use a standard user for routine work, JEA for delegated operations, JIT membership for the
short window that needs it, and tier-0 work only from a hardened administrative workstation.

Why it holds: the credential is not continuously attached to an elevated token. Do not report
"UAC enabled" as proof of tiering.

## Treating execution policy as application control

```powershell
Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine
```

A user can type the script at the command line instead. Microsoft explicitly says execution policy
is not a security system that restricts user actions.

Fix: use WDAC or AppLocker for application control, Constrained Language Mode for the effect, JEA
for the management surface, and script block logging/transcription for evidence.

Why it holds: these controls constrain what can execute and what the endpoint exposes. A signed,
malicious script is still a valid script under AllSigned, so signing alone is not the boundary.

## JEA endpoint with a dangerous cmdlet

A role capability that exposes `Start-Process`, `New-Service`, `Invoke-Expression`, `Invoke-Command`,
`Add-LocalGroupMember`, or `net.exe` has a management endpoint that can become general code execution.

Fix: expose exact cmdlets and exact parameters; use `ValidateSet` for resource names; avoid wildcard
cmdlet names; put role files in a trusted module path and ACL them read-only to operators.

Why it holds: `RestrictedRemoteServer` is NoLanguage with no providers or external programs by
default, but an allowed command can reopen the entire surface. The allowlist is the control.

## JEA custom function assumed to be constrained

Custom function bodies in `FunctionDefinitions` run in the system's default language mode and are
not subject to JEA's language constraints. A function that pipes user input to `Invoke-Expression`
or invokes an unconstrained provider is a privilege wrapper, not a safe helper.

Fix: keep functions small, typed, and allowlisted; use fully qualified module names where required;
never evaluate user input as PowerShell; test the effective endpoint with a non-admin account.

Why it holds: the only code that gets elevated is code you reviewed, rather than a script block that
inherits the user's input.

## Protecting LSASS in the registry and never rebooting

A `RunAsPPL` value in a configuration repository proves intent, not operation. A driver may fail to
load, a reboot may never have happened, or UEFI lock may change what the value means.

Fix: audit CodeIntegrity first, reboot, then confirm WinInit event 12. Enable Credential Guard and
check its status on the live host too.

Why it holds: the check is the running protected process, not a stale registry export. Microsoft
warns that unsupported LSA plug-ins fail once protection is enforced.

## Adding Domain Admin to Protected Users as a universal fix

Protected Users forces Kerberos AES, blocks NTLM and delegation, removes cached verifiers, and gives
the account a four-hour TGT lifetime. That is excellent for tested tier-0 humans and a lockout for
an account whose AES key or authentication path is not ready.

Fix: add a pilot group, reset migrated passwords so AES keys exist, test every admin workflow, and
never add service or computer accounts. Microsoft says the built-in Administrator is exempt.

Why it holds: the restrictions are non-configurable, so testing is the only safe migration path.

## Enabling Credential Guard without testing application compatibility

Credential Guard breaks unconstrained delegation, Kerberos DES, RC4, NTLMv1, TGT extraction, and
some uses of Digest, CredSSP, and credential delegation. Enabling it on an Exchange server is
unsupported; Microsoft does not recommend it on domain controllers.

Fix: inventory authentication and delegation first, test a representative host, then deploy by OU or
baseline. Do not disable it globally because one legacy application broke.

Why it holds: the exception is scoped to the incompatible workload and has an owner, while other
hosts retain the protection.

## Thinking a gMSA is a secret vault

A gMSA removes the human password and rotates its managed password. It does not stop the process
from accessing a share or database whose ACL grants the account broad rights, and it does not protect
network resources if the host itself is compromised.

Fix: narrow `PrincipalsAllowedToRetrieveManagedPassword` to exact hosts and grant the gMSA only the
specific share, SQL database, or endpoint permissions it needs.

Why it holds: identity lifecycle and authorization are separate controls. A perfect identity with
an `Everyone:FullControl` share is still an over-privileged application.

## Assuming constrained delegation is safe without reading the target list

Constrained delegation is safer than unconstrained but can still authorize a compromised front end
to impersonate users to every listed SPN. A list of twenty back ends is not least privilege.

Fix: prefer RBCD where the resource owner should decide, and make the target list exact. Audit write
access to the back-end computer object because that is now the security decision.

Why it holds: compromise of the front end yields only the resources whose owners granted it access.

## Using a human account with an SPN and a complex password

Any authenticated domain user can request a ticket for an SPN. The service account password is the
offline target. Complexity rules do not make a short password random or unguessable.

Fix: move the SPN to a gMSA. If impossible, use a long random password in a vault, force AES where
supported, and rotate it.

Why it holds: a gMSA's machine-generated password removes the offline guessing target rather than
asking a policy to make it less attractive.

## Quoting an ImagePath and stopping there

A quoted service path prevents whitespace search, but a non-admin-writable binary directory still
allows replacement. Conversely, a locked directory with an unquoted path still searches writable
parents.

Fix: quote the executable, inspect every parent ACL, lock the service registry key, and place state
in a separate directory.

Why it holds: parsing and permissions are separate attack primitives; both have to be closed.

## Putting the secret in the connection string "temporarily"

```json
"Default": "Server=sql01;Password=temporary;"
```

The secret is now in git history, build logs, backups, and developer workstations even after the line
is removed. `user-secrets` is for development and does not encrypt values.

Fix: integrated authentication with a gMSA, DPAPI, or a vault. Rotate a value that was committed;
deleting it is not remediation.

Why it holds: the secret never crosses the source-control boundary.

## Treating `customErrors` as the only error control

`customErrors` is for ASP.NET Framework. An ASP.NET Core app can still call
`UseDeveloperExceptionPage()` unconditionally, or a reverse proxy can expose a detailed upstream
response.

Fix: environment-gate the developer exception page, use `UseExceptionHandler` outside development,
set `customErrors` in Framework apps, and test a fault through the actual proxy.

Why it holds: the client receives a correlation-safe error while the full detail goes to protected
logs.

## Sharing a pool identity between applications

One compromise reads every file ACL'd to the shared identity. Moving the apps to separate directories
without separate identities is cosmetic.

Fix: one pool per application, `ApplicationPoolIdentity`, and `IIS AppPool\<PoolName>` ACLs. Keep
writable uploads/state outside the content root.

Why it holds: a pool's SID is unique to the pool, so a compromise does not cross the application
boundary through the file system.

## Sharing ASP.NET Core Data Protection keys without an application name

All nodes need the same key ring for cookies, antiforgery, and reset tokens. But two applications
sharing the ring and discriminator can also read each other's payloads.

Fix: shared, ACL'd, encrypted storage plus the same `SetApplicationName` on nodes of one app and a
different name per app.

Why it holds: the key ring is shared for availability while the application discriminator keeps
payload purposes separate. Per-key ACLs are not the isolation mechanism.

## Requiring SMB signing by setting the wrong value

`EnableSecuritySignature` is ignored for SMB2 and later. Setting it to 1 and declaring relay solved
is a no-op.

Fix: require signing with `RequireSecuritySignature=1` on both LanManWorkstation and LanManServer;
audit incompatible clients first.

Why it holds: the requirement is enforced at session negotiation, and unsigned peers cannot complete
the connection. Test legacy non-Microsoft clients before broad rollout.

## Enabling advanced audit policy but letting basic policy overwrite it

A higher-precedence basic audit policy can silently replace advanced subcategories. The host then
looks configured in a GPO backup while generating none of the expected events; 4719 is the clue.

Fix: enable "Audit: Force audit policy subcategory settings ... to override audit policy category
settings", then run `auditpol /get` on the host.

Why it holds: the effective policy is verified and the overwrite becomes an event, not a surprise.

## Collecting events without an alert or forwarding them

A Security log that nobody reads is storage. A local log that an administrator can clear is not a
forensic record.

Fix: forward to a SIEM or WEF collector, name the detection rule for every event, and alert when a
stream goes quiet. See `core/logging-audit`.

Why it holds: the event has an owner, an alert path, and an off-host copy.

## Treating BitLocker as a live-host control

BitLocker protects data at rest when a disk or image is offline. It does not stop an attacker with a
running session, a service token, or access to the mounted volume.

Fix: use TPM-backed BitLocker for disposal and theft risk, then still fix identity, ACLs, LSASS, and
application secrets.

Why it holds: each control covers a different state of the host.
