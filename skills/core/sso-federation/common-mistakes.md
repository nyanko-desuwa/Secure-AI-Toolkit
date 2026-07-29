# SSO Federation Common Mistakes

## "The assertion is signed"

A signature says who signed the selected XML node. It does not prove the assertion is for this SP,
this tenant, this ACS endpoint, or this login. Validate issuer, audience, recipient, destination,
time, and request binding.

## "Email is the identity"

Email can change and collide across tenants. Bind subject/NameID to the configured IdP and tenant;
apply an account-linking policy for existing local users.

## "Group claim equals local admin"

Claims are inputs from an external authority. Map only documented group identifiers to local roles,
default to least privilege, and review the mapping when tenants change.

## "Metadata refresh is harmless"

A metadata URL changes signing keys and endpoints - it changes who may authenticate. Authenticate and
review updates like any other trust-root change.
