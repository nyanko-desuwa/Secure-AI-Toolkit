# HTTP Client Security Examples

## Arbitrary URL fetch

```python
# Vulnerable: attacker selects destination
response = requests.get(request.json["url"])
```

```python
# Fixed: dependency identifier selects an allowlisted destination
response = requests.get(DEPENDENCIES[validated_name], timeout=(2, 5))
```

## Weak private-address check

```python
# Vulnerable: string check misses IPv6, redirects, and encodings
if "127.0.0.1" not in url: fetch(url)
```

```python
# Fixed: parse URL, resolve A/AAAA, classify addresses, then connect under egress policy
authorize_destination(url); fetch(url, redirect="error")
```

## Unsafe redirect

```javascript
// Vulnerable: credentials can follow cross-origin redirect
fetch(url, { headers: { Authorization: token }, redirect: "follow" });
```

```javascript
// Fixed: disable automatic redirects or reauthorize each hop
fetch(authorizedUrl, { redirect: "error" });
```

## TLS disabled

```python
# Vulnerable: interception becomes acceptable
requests.get(url, verify=False)
```

```python
# Fixed: use verified platform or scoped CA trust
requests.get(url, verify=ca_bundle, timeout=(2, 5))
```

## Unbounded response

```go
// Vulnerable: no deadline or byte limit
resp, _ := http.Get(url)
body, _ := io.ReadAll(resp.Body)
```

```go
// Fixed: client deadline and bounded reader
client := &http.Client{Timeout: 5 * time.Second}
body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
```

## Retry repeats a mutation

```python
# Vulnerable: retry can charge or send twice
retry_forever(lambda: post("/charge", body))
```

```python
# Fixed: bounded, idempotency-aware retry
post_with_idempotency(key, body, max_attempts=3)
```

## Credential in URL/log

```python
# Vulnerable: secret query string enters logs
logger.info("fetching %s", f"{url}?token={token}")
```

```python
# Fixed: headers and redacted structured telemetry
logger.info("outbound_request", extra={"origin": origin, "status": status})
```

## Real incident shape

An image-fetch endpoint accepted any URL and relied on an application denylist. A redirect reached a
cloud metadata/control-plane path. Parsed destination policy, redirect revalidation, and network
egress controls would have prevented the request or limited its blast radius.
