# HTTP Client Security Skill

Secure application-initiated HTTP(S), from destination construction to response handling.

## Coverage

Named stacks: Node fetch/undici, Python requests/httpx, Java HttpClient/Spring WebClient, .NET
HttpClient/IHttpClientFactory, and Go net/http. Their defaults and option names are
version-sensitive; use this skill's boundary controls, then verify the deployed library docs.

## Limitations

- Source review cannot prove live DNS answers, proxy policy, network egress, cloud metadata
  protection, or resolver rebinding behavior.
- Application URL filtering reduces SSRF but does not replace egress segmentation.
- Certificate pinning has rotation/availability costs; hostname and CA verification are the default.

## Security notes

Vulnerable examples are labelled and paired. Hostnames and credentials are synthetic.
