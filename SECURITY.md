# Security policy

Vantax is live and has **not** yet had an independent third-party audit.
Do not use it to custody value until a review of your specific deployment is
complete.

## Reporting a vulnerability

Report privately through GitHub:
**[Report a vulnerability](https://github.com/Vanta-Cybersecurity/Vantax/security/advisories/new)**
(the repository's Security tab, then "Report a vulnerability").

Please do not open a public issue, pull request or post for a security
problem. If you cannot use GitHub, send a direct message to
[@VantaxFounder](https://x.com/VantaxFounder) on X asking for a private
channel, without details of the problem.

A useful report says:

- which crate, version or commit, and which deployment setting it needs;
- what an attacker can do, and what they need first (a key, network access, an API key);
- how to reproduce it: a test, a request or a short program is ideal.

We will acknowledge the report, keep you informed while we fix it, agree a
disclosure date with you, and credit you in the advisory unless you would
rather not be named. There is no bug bounty yet.

## Supported versions

| Version | Supported |
|---|---|
| 2.x (this repository) | Yes |
| 1.x | No. Version 2.0 fixed a critical signature-verification flaw in 1.x; 1.x keys and signatures load unchanged in 2.x. |

## Scope

In scope: the crates in this repository (`vantax-core`, `vantax-adapters`,
`vantax-scan-common`, `vantax-gateway`, `vantax-cli`), the CI workflow, the site
in `site/`, and the hosted Vantax API at `api.vantax-cybersecurity.com`,
including scanning and Stripe billing. The server and the scanning engine are
not public: report what you can observe and reproduce from outside, against
your own key and your own subscription only. Billing is live, so purchases
are real payments.

Especially interesting:

- a signature, attestation or audit chain that verifies when it should not;
- any way to make the API or gateway sign bytes chosen by a caller;
- secret keys reaching a log, a response, an error message or a world-readable file;
- spending another key's quota, or bypassing rate limits or the policy;
- getting a paid plan or the scanner without a matching active Stripe
  subscription: a forged or replayed webhook, claiming someone else's key, or
  keeping a paid plan after a subscription ends;
- a vault that recovers with fewer shares than its threshold, or recovers the wrong data.

Out of scope: crates that are not in this repository yet (identity, sentinel,
bridge, fairness, wasm); vulnerabilities in dependencies that do not affect
Vantax (report those upstream, but do tell us if Vantax is affected);
volumetric denial of service; and findings from automated tools without a
demonstrated impact.

## Known limitations

These are documented behaviour, not vulnerabilities. Reports that show they
matter more than we think are still welcome.

- **No audit.** The code has tests and has been reviewed by its authors, not by
  an independent third party.
- **Signature metadata is not signed.** A `VantaxSignature`'s `message_hash`,
  `signer_fingerprint` and `timestamp` are descriptive. Verification checks
  the signature over the digest of the message you supply. To bind a time or
  context, put it in the signed message (`CanonicalMessage`).
- **Underlying implementation.** ML-DSA-87 comes from PQClean through
  `pqcrypto-mldsa`. Vantax relies on it for correctness and side-channel
  resistance and has not verified either independently.
- **Wiping secrets is best effort.** Vantax holds secret keys in zeroizing
  buffers, but copies made inside the underlying libraries and by the
  operating system (swap, core dumps) are outside its control.
- **The audit log detects tampering against a head you saved.** Each entry
  commits to the previous one, but whoever controls the data directory and the
  gateway key can rewrite the whole chain consistently. Keep audit heads or
  `audit-head` attestations somewhere the operator cannot change.
- **Gateway and API keys at rest.** The gateway's active signing key is stored
  unencrypted, owner-only, in `VANTAX_DATA_DIR`; protect that directory like a
  secret. Retired gateway keys keep only their public half. Customer API keys
  are stored as SHA3-256 hashes.
- **Billing trusts Stripe's signature.** Whoever holds the webhook signing
  secret can grant plans; keep it as secret as the admin token. The
  `session_id` on the post-checkout page is what proves a purchase: whoever has
  it first gets that purchase's key (once). It never leaves the customer's
  browser except to the API, and the welcome page removes it from the address
  bar and is excluded from nginx access logs. `billing.json` holds customer
  emails and Stripe ids; it is owner-only and never served.
- **Billing follows webhooks.** If a webhook is lost for good (Stripe retries
  for three days), a plan change is missed until the next event for that
  subscription. `GET /admin/billing/accounts` shows what the server believes.
- **One writer.** Run one API instance per data directory. Usage counters are
  flushed every 30 seconds, so a crash can lose up to 30 seconds of counts.
- **Vault time-locks are not cryptographic.** `not_before` is enforced by the
  tool and authenticated, so it cannot be edited without breaking decryption,
  but holders of enough shares with a modified tool can recover early.
- **The scanner is pattern-based.** It is a starting point for review, not an
  audit, and cannot see cryptography reached through opaque dependencies.
- **No chain verifies ML-DSA at consensus today.** Commitments and anchors are
  evidence, not on-chain enforcement.
