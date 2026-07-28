# Realtime Threat Mapping

Sources: OWASP API Security Top 10 2023, <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>; CWE, <https://cwe.mitre.org/>. Checked: 2026-07-28.

| Failure | Mapping |
|---|---|
| No connect authentication | API2 · CWE-306 |
| Cross-user room/subscription | API1 · CWE-639 |
| Admin event available to ordinary member | API5 · CWE-285 |
| Unbounded connections/messages/fan-out | API4 · CWE-770 |
| Missing browser Origin validation | CWE-352 class |
| Session/reconnect fixation | CWE-384 |
| Unvalidated message object | CWE-74 / CWE-915 |

A WebSocket frame is still untrusted input after the handshake.
