> Verified 2026-07-28 against Apple Developer Documentation (Security, BundleResources,
> AuthenticationServices, Xcode) via `developer.apple.com/documentation`.
> Behaviour changes between OS releases. Where a default depends on the SDK an app links
> against, that is stated.

# iOS platform reference

Keychain classes, App Transport Security, deep linking, and the privacy manifest - the parts a
reviewer needs to be exact about.

## Keychain accessibility classes

The accessibility attribute decides when the item can be read and whether it leaves the device.
Quoted abstracts from the Security framework documentation:

| Constant | When readable | Leaves the device? |
|---|---|---|
| `kSecAttrAccessibleWhenUnlocked` | "only while the device is unlocked by the user" | migrates via encrypted backup |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | same, foreground use | "do not migrate to a new device" |
| `kSecAttrAccessibleAfterFirstUnlock` | "cannot be accessed after a restart until the device has been unlocked once", then stays readable | migrates via encrypted backup |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | same as above | "never migrate to a new device" |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | "only when the device is unlocked. Only available if a passcode is set" | never migrates |
| `kSecAttrAccessibleAlways` | any time, locked or not | migrates via encrypted backup |
| `kSecAttrAccessibleAlwaysThisDeviceOnly` | any time, locked or not | never migrates |

Two facts to carry into a review:

- Both `Always` variants are documented as "not recommended for application use" and are marked
  deprecated as of iOS 12.0 / macOS 10.14 in the platform availability data. Treat their presence
  in current code as a finding.
- `WhenPasscodeSetThisDeviceOnly` is the strictest: no items can be stored in this class on a
  device without a passcode, and disabling the passcode deletes everything in the class. That is
  a real availability tradeoff, not a free upgrade.

Choosing: `WhenUnlockedThisDeviceOnly` for anything only needed in the foreground.
`AfterFirstUnlockThisDeviceOnly` when a background task or push handler must read it. The
`ThisDeviceOnly` suffix is what keeps the value out of a backup restored onto another device.

## Access control flags

`SecAccessControlCreateFlags` gates an item behind a local authentication check. Constraints
documented under it: `devicePasscode`, `biometryAny`, `biometryCurrentSet`, `userPresence`,
`watch`, plus the conjunctions `and` / `or` and the additional options `applicationPassword` and
`privateKeyUsage`. `touchIDAny` and `touchIDCurrentSet` are listed as legacy constraints.

`biometryCurrentSet` is the one to reach for when the item must be invalidated if the enrolled
set changes: "The item is invalidated if fingers are added or removed for Touch ID, or if the
user re-enrolls for Face ID." `biometryAny` survives an attacker enrolling their own finger after
coercing the passcode out of the user.

`LAContext` is the API for evaluating an authentication policy. Its documentation notes that the
`NSFaceIDUsageDescription` key must be in `Info.plist` for apps that allow biometric
authentication, "otherwise, authorization requests may fail". A `LAContext.evaluatePolicy`
result is a boolean your own code chooses to honour, so it gates UI, not data. Binding the key
material to the check via `kSecAttrAccessControl` is what makes the biometric decision
enforceable.

## App Transport Security

ATS lives under the `NSAppTransportSecurity` dictionary in `Info.plist`. From the documentation:
ATS "requires that all HTTP connections made with the url-loading-system - typically using the
`URLSession` class - use HTTPS", imposes extended checks on top of default TLS server trust
evaluation, and "blocks connections that fail to meet minimum security specifications".

Two behaviours that decide reviews:

- ATS operates by default for apps linked against the iOS 9.0 / macOS 10.11 SDK or later. Link
  against an older SDK and ATS is disabled regardless of the OS the app runs on.
- All keys in the dictionary are optional with defaults suitable for most apps. Global exception
  keys apply to every connection except those covered by `NSExceptionDomains`.

Documented keys:

| Key | Group |
|---|---|
| `NSAllowsArbitraryLoads` | global exception |
| `NSAllowsArbitraryLoadsForMedia` | global exception |
| `NSAllowsArbitraryLoadsInWebContent` | global exception |
| `NSAllowsLocalNetworking` | global exception |
| `NSExceptionDomains` | per-domain settings |
| `NSPinnedDomains` | certificate pinning |
| `NSRequiresNIAPTLSPackageVersion` | TLS package compliance |
| `NSExceptionRequiresNIAPTLSPackageVersion` | TLS package compliance |

`NSAllowsArbitraryLoads` is the one that shows up in shipped apps because it makes a proxy work
during development. It turns ATS off for everything. If a single legacy host genuinely needs
cleartext, scope it under `NSExceptionDomains` and leave the rest enforced.

Note the interaction the docs call out: if you specify any global exception other than
`NSAllowsArbitraryLoads`, ATS behaviour then depends on the OS version the app runs on. The
pattern is a coarse exception for older versions plus a targeted one for newer.

## Declarative pinning with NSPinnedDomains

Structure, from the documentation:

```text
NSPinnedDomains : Dictionary {
    <domain-name-string> : Dictionary {
        NSIncludesSubdomains : Boolean
        NSPinnedCAIdentities : Array
        NSPinnedLeafIdentities : Array
    }
}
```

For each domain you must supply one or more CA/sub-CA certificates under
`NSPinnedCAIdentities`, one or more leaf certificates under `NSPinnedLeafIdentities`, or both -
and if you specify both, ATS requires a match in each category. Pinning does not change any other
security requirement: pinning a CA certificate "doesn't change the way the system evaluates that
certificate's suitability as an anchor certificate".

Declarative pinning is preferable to a hand-written `URLSessionDelegate` trust callback, because
the common delegate mistake is to accept the server's chain unconditionally and thereby disable
verification entirely.

## Deep links: custom schemes versus Universal Links

Apple's own guidance on custom URL schemes: "While custom URL schemes are an acceptable form of
deep linking, universal links are strongly recommended." The reason it gives for the
recommendation is registration collision - the identifier you supply with your scheme
distinguishes your app from others declaring the same scheme, but "it doesn't prevent other apps
from registering the same scheme and handling the associated links."

The security warning in the same document is the one to quote in a review: URL schemes "offer a
potential attack vector into your app, so make sure to validate all URL parameters and discard
any malformed URLs. In addition, limit the available actions to those that don't risk the user's
data."

Universal Links work through associated domains. The app carries an
`com.apple.developer.associated-domains` entitlement; the site serves
`apple-app-site-association` from its `.well-known` directory, listing app identifiers in the
form `<Application Identifier Prefix>.<Bundle Identifier>` under the `applinks` service. When a
user installs the app, the system downloads the file and verifies the domains in the entitlement.
Each subdomain needs its own entry and its own association file.

The security difference: a custom scheme is a name any app can claim. A Universal Link requires
control of the HTTPS origin, so hijacking it means compromising the domain.

## OAuth in a system browser

`ASWebAuthenticationSession` is the supported way to run a web auth flow. Its documentation
states that it "ensures that only the calling app's session receives the authentication callback,
even when more than one app registers the same callback URL scheme" - which is the specific
attack a bare custom-scheme redirect is open to.

Relevant configuration: `prefersEphemeralWebBrowserSession` runs the flow without existing
cookies, so no shared sign-in state. The `init(url:callbackURLScheme:completionHandler:)`
initializer is listed under deprecated symbols; the current initializers take a `callback`
value, which supports HTTPS callbacks as well as custom schemes. Check the deployment target
before choosing.

Use `WKWebView` for content, not for someone else's login page. See
[oauth-native-apps.md](oauth-native-apps.md).

## Privacy manifest

`PrivacyInfo.xcprivacy` is a property list recording the app's or SDK's privacy practices. Top
level keys documented: `NSPrivacyTracking`, `NSPrivacyTrackingDomains`,
`NSPrivacyCollectedDataTypes`, `NSPrivacyAccessedAPITypes`.

Placement, from the documentation: root of the bundle for iOS, iPadOS, tvOS, visionOS, and
watchOS apps and frameworks; `Contents/Resources/` for macOS and Mac Catalyst apps;
`Versions/A/Resources/` for macOS frameworks. Swift packages need the file declared explicitly as
a resource - Xcode does not treat it as one by default. A static `.a` library cannot carry a
privacy manifest at all; it has to become a static framework first.

Two consequences for a review:

- App Store Connect rejects submissions containing invalid privacy manifest files. An invalid
  manifest inside a third-party SDK is your release blocker, not theirs.
- Every third-party SDK you ship needs its own valid manifest. If an SDK you depend on does not
  have one, that is a supply-chain finding with a delivery date attached.

## Sources

- Keychain accessibility constants - <https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly>
- `SecAccessControlCreateFlags` - <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags>
- `LAContext` - <https://developer.apple.com/documentation/localauthentication/lacontext>
- `NSAppTransportSecurity` - <https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity>
- `NSPinnedDomains` - <https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nspinneddomains>
- Custom URL schemes - <https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app>
- Associated domains - <https://developer.apple.com/documentation/xcode/supporting-associated-domains>
- `ASWebAuthenticationSession` - <https://developer.apple.com/documentation/authenticationservices/aswebauthenticationsession>
- Privacy manifest files - <https://developer.apple.com/documentation/bundleresources/privacy-manifest-files>
