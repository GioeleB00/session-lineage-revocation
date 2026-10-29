# Session ID Rotation and Revocation: Should Rotating Identifiers Share a Common Revocation Boundary?

**Status:** Design discussion — request for community feedback  
**Author:** Gioele Botta ([@GioeleB00](https://github.com/GioeleB00))  
**Date:** 29 October 2026  
**Context:** Server-side HTTP sessions; `lua-resty-session` 4.1.5 with Redis, as used in an OIDC integration

This document raises a **session-management design question**, not a vulnerability claim. The observed behavior is consistent with the library's current design, as confirmed during a security discussion with Apache. The goal is to examine a stronger *revocation guarantee* and its trade-offs, particularly in light of OWASP's guidance on session ID renewal.

## 1. Problem: a rotated SID can produce an independently revocable branch

`lua-resty-session` supports `stale_ttl` (10 seconds by default). After a session save rotates the session ID, the previous ID remains temporarily usable to accommodate requests from the same browser that were already in flight. In the Redis-backed implementation, a save issues a fresh SID and reduces the previous record's expiry to the configured stale interval.

Consider this experimentally observed sequence:

```text
Attacker copies the victim's authenticated session cookie (SID A)
Victim's session rotates: A -> B
Attacker reuses A during stale_ttl and a save produces SID C
Victim logs out using B; B is revoked
Attacker continues authenticating with C until its applicable timeout
```

A control run also created C *before* the logout, showing that the revocation outcome does not depend on a precisely timed race with logout. The absolute timeout remained enforced. The attacker already possessed a valid bearer credential, so the proposal does not claim to prevent impersonation before revocation, nor does it request a CVE.

The question is instead: **should a single authenticated session be able to branch through ordinary SID rotation into independently revocable authenticated sessions?** In this scenario, the victim cannot terminate the attacker's derived access merely by logging out of B.

## 2. Proposed security invariant

**After logout of a logical authenticated session has completed, no SID associated with that same session—current, stale, or concurrently derived—should authenticate a new request or create a fresh authenticated session.**

This applies to the authentication decision after the revocation completes, not retroactively to requests already authorized. A concurrently running save or rotation must not resurrect the revoked session.

Importantly, this is **session-lineage revocation**, *not* subject-wide revocation: if the same user logs in independently on another device, that separate login remains valid. Nor does the proposal require revoking the user's identity-provider (IdP) session.

## 3. Conceptual alternative: one logical session, rotating identifiers

Separate the authenticated session from the bearer identifiers that refer to it:

```text
             Login
               |
       Logical session F1
       (active / revoked)
               |
          +----+----+
          |         |
      SID A       SID B
      (stale)     (current)
          |         |
          +----+----+
               |
         Same F1 state
               |
          Logout F1
               |
       A and B both fail
```

At login, establish a stable **logical session F1**. During ordinary, non-privilege-changing rotation, A is replaced by B, but both identifiers (for as long as A is eligible) refer to **F1 rather than separate authenticated lineages**. A request carrying stale A may be accepted under a bounded grace policy, but it must not create an independently revocable session C. Whether a stale request receives B, completes without a new cookie, or is asked to retry is a separate design choice.

Logout revokes F1. Every identifier resolving to F1, including one still within `stale_ttl`, is then rejected for subsequent authentication. Independent login F2, even for the same subject, is unaffected.

This is a **conceptual model**, not a claim that it can be implemented safely with a simple SID-to-session lookup. In particular, concurrent rotation and logout would need a well-defined ordering and an authoritative revocation state.

## 4. Security and engineering trade-offs

**A stolen stale SID remains useful during grace.** The proposal cannot distinguish an attacker holding A from a legitimate concurrent request. Returning B to a holder of A may also promote a stolen credential. The claimed improvement is limited but important: both A and B would remain inside the *same revocation boundary*.

**Concurrency and browser behavior are nontrivial.** Parallel requests, out-of-order `Set-Cookie` responses, state updates and retries may cause lost updates or session disruption. A design must specify what stale requests can do, not just which SID they resolve to.

**Revocation must be race-safe.** A request that read F1 as active immediately before logout cannot be allowed to re-create valid authentication state afterward. Distributed gateway workers, storage failures, and stale caches require careful coordination; this may cost more than the library's existing lockless model.

**Scope matters.** Grace aliases should not cross login or privilege-elevation boundaries. In multi-audience sessions, the meaning of an application logout versus full-lineage revocation must be explicit. Session-family revocation also does not replace IdP back-channel logout or subject-wide account revocation.

OWASP's [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) describes a safety interval during session ID renewal and cautions about the associated hijacking race. It does **not** require independently revocable descendants or prescribe a 10-second interval. The proposed model appears consistent with its distinction between a session and its identifiers, but that is precisely the judgment on which community review is sought—not a claim of formal OWASP compliance.

## 5. Questions for the community

1. Is **logout-revokes-the-session-lineage** a useful security invariant for general-purpose server-side session management, distinct from subject-wide revocation?
2. Could a stable logical session with rotating SID aliases offer a safer revocation model while retaining the concurrency tolerance described by OWASP? What important counterexamples or weaknesses are missing?

**References:** [OWASP — Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renewal-timeout) · [`lua-resty-session` v4.1.5 (`save` / `logout`)](https://github.com/bungle/lua-resty-session/blob/v4.1.5/lib/resty/session.lua) · [`lua-resty-session` Redis storage](https://github.com/bungle/lua-resty-session/blob/v4.1.5/lib/resty/session/redis/common.lua) · [NIST SP 800-63B — Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/)
