# Deserialization Security Examples

## Python pickle - CWE-502

```python
# Vulnerable: deserializes behavior-carrying bytes
value = pickle.loads(request.body)
```

```python
# Fixed: strict data-only model
value = InvoiceInput.model_validate_json(request.body)
```

## Java ObjectInputStream - CWE-502

```java
// Vulnerable: reads a foreign object graph
Object value = new ObjectInputStream(input).readObject();
```

```java
// Fixed: reads bounded data into explicit DTO
Invoice value = mapper.readValue(body, Invoice.class);
```

## .NET BinaryFormatter - CWE-502

```csharp
// Vulnerable: formatter.Deserialize(stream)
```

```text
Fixed: supported data contract/JSON DTO with explicit fields, limits, and versioning.
```

## Unsafe YAML - CWE-502

```python
# Vulnerable: yaml.load(text, Loader=yaml.Loader)
```

```python
# Fixed: yaml.safe_load(text)
```

## XML external entity - CWE-611

```text
Vulnerable: parser resolves external entities from an untrusted document.
Fixed: external entities/network resolution disabled before parsing.
```

## PHP unserialize - CWE-502

```php
// Vulnerable: $value = unserialize($_POST['state']);
```

```php
// Fixed: $value = json_decode($_POST['state'], true, 512, JSON_THROW_ON_ERROR);
```

## Polymorphic type field - CWE-502

```text
Vulnerable: client-controlled type name selects a server class.
Fixed: server owns a small allowlisted discriminator mapped to data-only DTOs.
```
