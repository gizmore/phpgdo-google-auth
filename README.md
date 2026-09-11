# GoogleAuth

Google sign-in for PHPGDO sites, implemented as an OpenID Connect (OIDC)
provider module. It adds an optional **Continue with Google** action to the
registration and login forms without making Google a requirement for a normal
PHPGDO account.

## Scope

The initial module deliberately requests only the identity scopes:

```text
openid email profile
```

It does not request Drive, Contacts, Calendar, Gmail, or any other Google API
permission. A Google account is identified by its stable OIDC `sub` claim,
never by its display name and never solely by its e-mail address.

## Intended flow

1. A visitor chooses **Continue with Google**.
2. `GoogleAuth` creates an expiring, single-use `state` value and OIDC `nonce`
   bound to the PHPGDO session.
3. The browser is sent to Google's authorization endpoint using the
   authorization-code flow with PKCE.
4. The callback validates `state`, exchanges the code server-side, and
   verifies the ID token signature, issuer, audience, expiry, and nonce using
   Google's JWKS.
5. The verified `sub` maps to one local Google-auth identity.
6. The module signs in the associated user. For a previously unknown Google
   identity, it links the identity to the one existing local account with the
   same verified e-mail address, or creates a new account if none exists.

Tokens are not needed after identity verification and should not be persisted
in the first version. This keeps the feature focused on sign-in rather than
becoming a Google API client.

## Data model

The module should own a small mapping table, conceptually:

| Column | Meaning |
| --- | --- |
| `gauth_id` | Local primary key |
| `gauth_user` | Linked PHPGDO user |
| `gauth_subject` | Google OIDC `sub`; unique |
| `gauth_email` | Last verified e-mail, informational only |
| `gauth_created` / `gauth_updated` | Audit timestamps |

The provider subject and local e-mail address are both unique. This prevents
two local accounts from claiming one Google identity and prevents duplicate
accounts for the same login address. A user may unlink Google only while
another usable login method remains.

## Configuration

The module will need these server-side configuration values:

| Key | Purpose |
| --- | --- |
| `google_auth` | Enable the sign-in buttons and callback |
| `google_client_id` | OAuth client ID |
| `google_client_secret` | OAuth client secret; stored as a secret config value |
| `google_redirect_uri` | Exact registered HTTPS callback URI |

The Google Cloud Console must register the same HTTPS callback URI. Development
uses a separate OAuth client; production credentials must never be placed in a
seed, repository, JavaScript bundle, or browser-visible configuration.

## Dependencies

Required: `Login`, `Register`, `Session`, `User` and an HTTP/JWT-capable
implementation. Optional integrations:

- `Avatar` to import the profile picture only after the account holder agrees.
- `Mail` to copy a verified address during new-account creation.

`GoogleAuth` must remain usable when the optional modules are disabled.

## Security requirements

- Authorization-code flow with PKCE, `state`, and `nonce`.
- Strict callback redirect URI; no user-supplied redirect destinations.
- Verify the ID token locally against Google's rotating JWKS and accepted
  issuer/audience values; do not trust profile fields supplied by the browser.
- Treat e-mail as verified only when the validated token says `email_verified`.
- Rate-limit callback failures and log only non-sensitive identifiers.
- Never show an account-selection result that reveals whether an e-mail exists
  locally.

## Account-link policy

Local login e-mail addresses are unique. When an unknown Google OIDC subject
returns a validated token with `email_verified=true`, the module links it to
the one local account with that e-mail address. If no such account exists, it
creates a new account. It must reject an already-linked Google subject rather
than moving it to another account.

This keeps e-mail login and Google login as two routes to the same local
account. The implementation must never make this decision from an unverified
e-mail claim or browser-supplied profile data.

## Implementation plan

1. Add module configuration, language files, `GDO_GoogleAuthIdentity`, and
   database migration.
2. Add the login/register button and the authorization-start method.
3. Implement session-bound state/nonce/PKCE handling and the callback.
4. Add explicit account linking/unlinking in account settings.
5. Add tests for token-claim validation, state replay, duplicate subjects,
   account-linking policy, and disabled optional dependencies.
