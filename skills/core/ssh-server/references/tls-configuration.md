# TLS Configuration

Set modern transport defaults at the TLS-terminating edge. Verified 2026-07-28 against Mozilla
Server Side TLS guidelines 5.7
(<https://ssl-config.mozilla.org/guidelines/5.7.json>). The old generator UI redirects to
<https://configurator.tlsref.org/>.

`A02:2025` · `A04:2025` · ASVS V12, V13 · CWE-16, CWE-295, CWE-327.

## Intermediate profile values

Use this profile unless every client supports TLS 1.3 and you deliberately choose Modern.

| Setting | Value |
|---|---|
| Protocols | TLS 1.2 and TLS 1.3 |
| Cipher preference | Client order; `ssl_prefer_server_ciphers off` |
| DH parameters | 2048-bit |
| ECDH curves | X25519, prime256v1, secp384r1 |
| Certificate | RSA or ECDSA, 2048-bit minimum |
| HSTS minimum age | 63072000 seconds |

```text
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
```

This is an explicit AEAD/forward-secrecy allowlist. TLS 1.3 suites are negotiated separately.
Do not append a vague exclusion denylist.

## Nginx TLS and edge block

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
ssl_session_cache shared:TLS:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
server_tokens off;
client_max_body_size 10m;
client_header_timeout 10s;
client_body_timeout 10s;
send_timeout 30s;
keepalive_timeout 30s;

set_real_ip_from 10.0.0.0/8;  # replace with the actual proxy subnet
real_ip_header X-Forwarded-For;
real_ip_recursive on;

location ~ /\.(?!well-known/) { deny all; }
location ~* (^|/)(\.git|\.env|\.svn|\.hg)(/|$) { return 404; }
location @app {
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_pass http://app;
    proxy_connect_timeout 5s;
    proxy_read_timeout 30s;
}
```

`set_real_ip_from` is mandatory. Without a trusted-source boundary, clients spoof
`X-Forwarded-For` and poison logs, rate limits, and IP allowlists (A02 · ASVS V13 · CWE-345).
`add_header ... always` preserves headers on errors. Location-level `add_header` declarations can
discard inherited server headers; repeat the full set or keep declarations at server level.

Do not serve directory listings (`autoindex off`, the default), dotfiles, `.git`, or `.env`.

OCSP stapling is not active for Let's Encrypt-only certificates: URLs were removed 2025-05-07 and
responders shut down 2025-08-06. Keep stapling only for a CA that still supports it. Confirm with
`openssl s_client -connect example.com:443 -servername example.com -status`.

## Apache equivalents

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder off
SSLSessionTickets off
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
ServerTokens Prod
ServerSignature Off
TraceEnable Off
Options -Indexes
AllowOverride None
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
LimitRequestBody 10485760
```

`ServerTokens Prod` still emits a minimal `Server` header. It is noise reduction, not concealment.

## Verify

```bash
nginx -t && nginx -T | grep -E 'ssl_protocols|add_header|client_max_body_size'
openssl s_client -connect example.com:443 -tls1_1 -servername example.com < /dev/null  # must fail
curl -sSI https://example.com/missing | grep -i strict-transport
```

Sources: Mozilla 5.7 above; Let's Encrypt OCSP announcement
(<https://letsencrypt.org/2024/12/05/ending-ocsp/>); CIS NGINX Benchmark 3.0.0 catalogue
(<https://www.cisecurity.org/cis-benchmarks>), all checked 2026-07-28.
