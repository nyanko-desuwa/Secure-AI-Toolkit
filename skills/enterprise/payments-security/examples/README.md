# Payments Security Examples

Vulnerable and fixed code pairs. Each pair targets a specific failure mode.

## Example 1: PAN captured by server

Vulnerable: form posts card number directly to your API
```html
<!-- Vulnerable: raw card data sent to your server -->
<form action="/api/pay" method="POST">
  <input name="number" placeholder="Card number">
  <input name="cvc"    placeholder="CVC">
  <input name="expiry" placeholder="MM/YY">
  <button>Pay</button>
</form>
```

Fixed: Stripe.js sends a token; your server receives only `payment_method`
```javascript
// Fixed
const {error, paymentMethod} = await stripe.createPaymentMethod({
  type: 'card',
  card: elements.getElement('card'),
});
if (error) { showError(error.message); return; }
await fetch('/api/pay', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({payment_method_id: paymentMethod.id}),
});
```

## Example 2: Webhook accepted before signature check

Vulnerable:
```python
# Vulnerable: order fulfilled before signature verified
@app.post('/webhook')
def webhook():
    body = request.get_json(force=True)
    if body.get('type') == 'payment_intent.succeeded':
        fulfill(body['data']['object']['metadata']['order_id'])
    # signature check happens after -- too late
    stripe.Webhook.construct_event(
        request.data,
        request.headers['Stripe-Signature'],
        WH_SECRET
    )
    return '', 200
```

Fixed:
```python
# Fixed: signature first; body parsed only on success
@app.post('/webhook')
def webhook():
    try:
        event = stripe.Webhook.construct_event(
            request.data,
            request.headers.get('Stripe-Signature', ''),
            WH_SECRET,
        )
    except stripe.error.SignatureVerificationError:
        return '', 400
    if event['type'] == 'payment_intent.succeeded':
        fulfill(event['data']['object']['metadata']['order_id'])
    return '', 200
```

## Example 3: client_secret exposed in URL

Vulnerable:
```python
# Vulnerable: client_secret in redirect -- in browser history, server logs, Referer header
intent = stripe.PaymentIntent.create(amount=1000, currency='usd')
return redirect(f'/checkout?secret={intent.client_secret}&order={order.id}')
```

Fixed:
```python
# Fixed: deliver client_secret in JSON body only
intent = stripe.PaymentIntent.create(amount=1000, currency='usd')
return jsonify({'clientSecret': intent.client_secret, 'orderId': order.id})
```

## Example 4: 3DS return trusted without server verification

Vulnerable:
```javascript
// Vulnerable: /complete called from query string; no server-side intent check
app.get('/complete', async (req, res) => {
  const {payment_intent, order_id} = req.query;
  await fulfillOrder(order_id);           // no check that intent actually succeeded
  res.redirect('/thanks');
});
```

Fixed:
```javascript
// Fixed: retrieve intent from Stripe; compare against order's stored intent id
app.get('/complete', async (req, res) => {
  const {order_id} = req.query;
  const order = await db.orders.findById(order_id);
  // Retrieve intent using ID stored server-side at order creation -- NOT from query string
  const intent = await stripe.paymentIntents.retrieve(order.stripeIntentId);
  if (intent.status !== 'succeeded') {
    return res.status(402).json({error: 'payment_not_confirmed'});
  }
  await fulfillOrder(order.id);
  res.redirect('/thanks');
});
```

## Example 5: CVC2 in log

Vulnerable:
```python
# Vulnerable: full request body logged -- CVC2 captured
logger.debug('charge request %s', request.json)
# Output: charge request {'card': {'number': '4242...', 'cvc': '123', 'exp_month': 12}}
```

Fixed:
```python
# Fixed: redact sensitive fields before any log statement
_REDACTED = ('number', 'cvc', 'cvv', 'cvc2', 'exp_month', 'exp_year', 'expiry')

def mask_card(obj):
    if isinstance(obj, dict):
        return {k: '***' if k in _REDACTED else mask_card(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_card(i) for i in obj]
    return obj

logger.debug('charge request %s', mask_card(request.json))
```

## Example 6: Idempotency key from client

Vulnerable:
```python
# Vulnerable: attacker can replay by reusing the same key for a different order
@app.post('/charge')
def charge():
    key = request.json['idempotency_key']        # client-supplied
    stripe.PaymentIntent.confirm(
        request.json['intent_id'],
        idempotency_key=key,
    )
```

Fixed:
```python
# Fixed: server-derived key tied to order identity
import hashlib

@app.post('/charge')
def charge():
    order = get_order(request.json['order_id'])
    key = hashlib.sha256(
        f'order:{order.id}:attempt:{order.attempt_count}'.encode()
    ).hexdigest()
    stripe.PaymentIntent.confirm(order.stripe_intent_id, idempotency_key=key)
```

## Example 7: Live key in frontend bundle

Vulnerable:
```javascript
// vite.config.js -- Vulnerable: sk_live exposed in bundle
export default {
  define: {
    'process.env.STRIPE_KEY': JSON.stringify(process.env.STRIPE_SECRET_KEY),
  }
}
// => bundle.js: stripe.charges.create({..., key: "sk_live_abc123"})
```

Fixed:
```javascript
// Fixed: only publishable key in the browser; secret key stays server-side only
const stripe = Stripe(import.meta.env.VITE_STRIPE_PUBLIC_KEY);  // pk_live_...
// All API calls that need sk_live_... go through your backend
```
