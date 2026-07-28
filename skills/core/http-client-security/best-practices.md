# HTTP Client Security Best Practices

## Prefer dependency IDs over free-form URLs

```python
# Vulnerable: attacker supplies the entire destination
requests.get(user_url, timeout=5)
```

```python
# Fixed: map a logical dependency to a constructed destination
url = ALLOWED_DEPENDENCIES[name]
requests.get(url, timeout=(2, 5))
```

## Validate every hop, not only the first host string

```javascript
// Vulnerable: host string check only, redirects enabled
if (!url.includes("example.com")) throw new Error("blocked");
await fetch(url, { redirect: "follow" });
```

```javascript
// Fixed: parse, resolve policy, and revalidate redirects or disable them
const destination = authorizeDestination(url);
await fetch(destination, { redirect: "error" });
```

## Keep TLS verification on

```python
# Vulnerable: certificate validation disabled "temporarily"
requests.get(url, verify=False)
```

```python
# Fixed: platform trust store or explicit CA; hostname verification remains enabled
requests.get(url, verify=settings.CA_BUNDLE, timeout=(2, 5))
```
