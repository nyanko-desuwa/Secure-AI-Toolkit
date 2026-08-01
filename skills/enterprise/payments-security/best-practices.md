# Payments Security Best Practices

Each pattern shows the vulnerable shape first, then the fixed shape.

## 1. Server never receives PAN

Vulnerable: custom payment form posts card number to your server
```html
<!-- Vulnerable: card number goes through your server -->
<form action="/api/charge" method="POST">
  <input name="card_number" ...>
  <input name="cvc" ...>
  <input name="expiry" ...>
</form>
```

Fixed: Stripe.js handles the card number; your server receives a token
```javascript
// Fixed: Stripe.js tokenizes in-browser; server receives payment_method only
const {paymentMethod, error} = await stripe.createPaymentMethod({
  type: 'card',
  card: cardElement,   // CardElement, never a raw number
});
// paymentMethod.id is all you send to your server
await fetch('/api/charge', {
  method: 'POST',
  body: JSON.stringify({payment_method_id: paymentMethod.id, amount: 1000}),
});
```

## 2. Webhook signature verified before body is parsed

Vulnerable: body read and acted on before signature check
```python
# Vulnerable: order updated before verifying the event is real
@app.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    data = request.get_json()            # body parsed first
    if data['type'] == 'payment_intent.succeeded':
        fulfill_order(data['data']['object']['metadata']['order_id'])   # acted on
    sig = request.headers.get('Stripe-Signature')
    stripe.Webhook.construct_event(request.data, sig, WH_SECRET)       # verified last
    return '', 200
```

Fixed: signature verified; body rejected on failure
```python
# Fixed: verify signature first, parse only on success
@app.route('/webhooks/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.data           # raw bytes, not parsed yet
    sig = request.headers.get('Stripe-Signature', '')
    try:
        event = stripe.Webhook.construct_event(payload, sig, WH_SECRET)
    except stripe.error.SignatureVerificationError:
        return '', 400               # reject; do not process
    if event['type'] == 'payment_intent.succeeded':
        fulfill_order(event['data']['object']['metadata']['order_id'])
    return '', 200
```

## 3. Idempotency key scoped server-side

Vulnerable: key derived from client input
```python
# Vulnerable: client sends idempotency_key; attacker can replay charges
@app.post('/charge')
def charge():
    key = request.json['idempotency_key']   # client-controlled
    stripe.PaymentIntent.confirm(intent_id, idempotency_key=key)
```

Fixed: key generated server-side, scoped to (order, attempt)
```python
# Fixed: server generates the key
import hashlib, os

def make_idempotency_key(order_id: str, attempt: int) -> str:
    raw = f"order:{order_id}:attempt:{attempt}"
    return hashlib.sha256(raw.encode()).hexdigest()

@app.post('/charge')
def charge():
    order = get_order(request.json['order_id'])
    key = make_idempotency_key(order.id, order.attempt_count)
    stripe.PaymentIntent.confirm(order.stripe_intent_id, idempotency_key=key)
```

## 4. 3DS completion validated server-side

Vulnerable: client-side redirect trusted unconditionally
```javascript
// Vulnerable: /complete called from browser redirect; order fulfilled without server check
app.get('/complete', async (req, res) => {
  const { payment_intent } = req.query;
  await fulfillOrder(payment_intent);   // no server-side verification of intent status
  res.redirect('/success');
});
```

Fixed: server fetches intent and checks status before fulfilling
```javascript
// Fixed: retrieve intent from Stripe API; never trust the redirect query param alone
app.get('/complete', async (req, res) => {
  const { payment_intent_client_secret, order_id } = req.query;
  const order = await db.orders.findById(order_id);
  const intent = await stripe.paymentIntents.retrieve(order.stripe_intent_id);
  if (intent.status !== 'succeeded') {
    return res.status(402).json({error: 'Payment not confirmed'});
  }
  await fulfillOrder(order.id);
  res.redirect('/success');
});
```

## 5. CVC2 never persisted

Vulnerable: CVC2 stored in a request log or model field
```python
# Vulnerable: entire payment request body logged -- includes cvc2
logger.info("payment request: %s", request.json)
# {'card_number': '4242...', 'cvc2': '123', 'expiry': '12/27'}
```

Fixed: card fields masked before logging; never stored
```python
# Fixed: mask sensitive fields before any logging
import copy

def safe_log(payload: dict) -> dict:
    safe = copy.deepcopy(payload)
    for field in ('card_number', 'cvc2', 'cvv', 'cvc', 'expiry'):
        if field in safe:
            safe[field] = '***'
    return safe

logger.info("payment request: %s", safe_log(request.json))
```

## 6. client_secret kept off URLs and logs

Vulnerable: client_secret in a redirect URL
```python
# Vulnerable: client_secret visible in browser history and server access logs
return redirect(f'/complete?client_secret={intent.client_secret}&order={order.id}')
```

Fixed: client_secret delivered in the JSON response, never in a URL
```python
# Fixed: return it in the response body, not a URL parameter
return jsonify({'client_secret': intent.client_secret})
# Browser-side JS reads it from the response body and calls stripe.confirmPayment(clientSecret)
```
