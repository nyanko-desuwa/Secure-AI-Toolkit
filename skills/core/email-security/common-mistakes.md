# Common Email Security Mistakes

## SPF alone is treated as sender trust

SPF does not sign message content, survives forwarding poorly, and does not establish aligned
DKIM/DMARC policy. Record aligned SPF, DKIM, DMARC, reporting, and who can change DNS.

## A resend endpoint is treated as harmless

Resends can enumerate accounts, flood a victim, and make a stolen inbox more valuable. `authentication`
owns token lifecycle; `brute-force-defense` owns request budgets and uniform responses.

## Bounces are processed as trusted account changes

Provider events are attacker-controlled until raw-body signature, freshness, replay, schema, and
recipient/tenant binding are checked. A delivery callback is not an authorization bypass.

## Retry means send again forever

Bound retries, use a message identity/outbox, and distinguish a provider timeout from confirmed
non-delivery. Repeated security mail can become an abuse channel.
