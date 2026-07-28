# Deserialization Best Practices

## Replace pickle with data — CWE-502

```python
# Vulnerable: input bytes can carry Python object behavior
value = pickle.loads(request.body)
```

```python
# Fixed: parse data-only JSON into a strict schema
value = InvoiceInput.model_validate_json(request.body)
```

## Do not deserialize Java objects from a socket — CWE-502

```java
// Vulnerable: ObjectInputStream reads untrusted object graph
Object value = new ObjectInputStream(socket.getInputStream()).readObject();
```

```java
// Fixed: parse a bounded JSON DTO with explicit fields
Invoice value = jsonMapper.readValue(boundedBody, Invoice.class);
```

## Use safe YAML loading — CWE-502

```python
# Vulnerable: YAML loader may construct tagged objects
data = yaml.load(text, Loader=yaml.Loader)
```

```python
# Fixed: data-only loader
data = yaml.safe_load(text)
```

## Disable XML external entities — CWE-611

```python
# Vulnerable: default XML parser configuration processes untrusted document
root = etree.fromstring(xml)
```

```python
# Fixed: parser resolves no entities and forbids network access
parser = etree.XMLParser(resolve_entities=False, no_network=True)
root = etree.fromstring(xml, parser)
```

## Retire BinaryFormatter — CWE-502

```text
Vulnerable: BinaryFormatter deserializes a client-provided blob.
Fixed: use a supported data contract/JSON representation with explicit type and size limits.
```

Why: authentication around an unsafe format does not make all future senders trustworthy.
