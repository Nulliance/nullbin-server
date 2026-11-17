# External audit follow-up, 2026-11-17

The supplied report reviewed commit `7771235`. It reported nine low-severity
findings and thirty numbered informational observations (the summary's count
of twenty-one informational findings does not match its own table).
No new cryptographic or protocol format is introduced by these fixes.

## Low-severity findings

| Item | Disposition |
| --- | --- |
| L1 | Pending tokens and capacity expire at the original invite deadline, including after an announcement. Owner admission must finish before then. Admitted members remain active. The join form asks for a hinted password before consuming the invite. Numbered slots and used invites remain non-reusable. |
| L2 | Startup uses `Lstat` and skips top-level links, junctions and non-directories, reporting a count. Other unreadable entries receive a full-budget charge so recovery works and writes fail closed. Stats no longer hide listing/accounting errors. |
| L3 | Paste, preview and discussion scans warn on U+2800 and all private-use planes. Display-label stripping also removes private-use and lone surrogate characters. Existing chat text rules remain compatible. |
| L4 | Every discussion author is explicitly labelled “Unverified name”, with an explanation that neither identity nor an official role is verified. This applies to old and new comments, including hostile authenticated payloads. |
| L5 | Expensive per-joiner checks stop after 4,096 occurrences and conservatively warn. Ordinary emoji and scripts retain their normal handling; text is not silently marked safe beyond the budget. |
| L6 | The npm build records source and output hashes and its version. Go embeds the exact build inputs and rejects stale sources, missing manifests, changed output bytes and explicit version mismatches at startup. No checkout or VCS metadata is required at runtime. Frontend-only builds explain that they do not refresh embeds. |
| L7 | Runtime images carry a Nullbin label; cleanup prunes only dangling images with that label and keeps shared build caches. Older unlabelled images are intentionally kept. |
| L8 | A separate 16-slot gate bounds chunk fsync and metadata commits. Streaming bodies acquire no durability slot, and existing mutation limits remain in place. |
| L9 | Shared Cloudflare configuration enables `trusted_proxies_strict`, retaining `CF-Connecting-IP` as the only parsed client header. This is topology hardening, not a confirmed bypass of Cloudflare-only deployments. |

## Informational observations

Some observations describe deliberate guarantees or unavoidable trust boundaries.
Changing those merely to eliminate an observation would weaken the product or
misrepresent what encryption can establish.

| Item | Disposition |
| --- | --- |
| I1 | Retained: the prefix endpoint permits non-consuming previews. IDs are 128-bit capabilities; possession can reveal existence. |
| I2 | Retained: prefix hints cannot establish authenticity. Authenticated decryption and full verification remain mandatory before content is shown. A server can deny service or lie about availability. |
| I3 | Retained: an AEAD failure cannot reliably distinguish an incorrect secret from damaged authenticated data. No partial content is published. |
| I4 | Documented limitation: browser countdowns depend on the local clock; server expiry remains authoritative for HTTP access. |
| I5 | Retained: empty attachments are legitimate encrypted content. The encrypted paste itself still has a nonzero bounded format. |
| I6 | Already handled in the reviewed source: limited burn responses set `Nullbin-Reads-Remaining`, including zero for a single-open paste. Legacy client responses without the header remain supported. |
| I7 | Already documented: the 32 KiB allocation overhead includes metadata, block rounding and temporary files. |
| I8 | Retained capability model: holders of a secret ID can learn availability. Wrong tokens and unknown objects remain uniform where token authorization applies. |
| I9 | API documentation now distinguishes JSON application errors from the HTTP router's plain-text 404/405 responses. |
| I10 | Retained Go standard-library cross-origin protection: browsers control Fetch Metadata. Non-browser clients can already supply arbitrary Origin headers. |
| I11 | Retained bounded, fail-closed limiter maps, with existing per-network and memory tradeoffs. |
| I12 | Retained exact-origin CORS and `no-store`. Static responses do not vary by Origin. |
| I13 | Retained deliberate HEAD rejection on paste reads: HEAD cannot consume a burn open. Its Allow header lists the actual supported GET and DELETE operations. |
| I14 | Documented canonical-path requirement; router slash normalization remains standard Go behavior. |
| I15 | Retained: authorizing a burn read consumes the open even when the transfer is interrupted. This prevents retry races from creating extra opens. |
| I16 | Documented: unknown storage directories remain charged until the operator removes them. Automatically deleting unknown local data would be destructive. Non-directories are skipped and counted. |
| I17 | Capacity error text now says “paste or storage capacity reached”, covering both bounds without exposing extra object details. |
| I18 | Directory listing errors fail stats; per-entry accounting errors are counted, mark totals incomplete and make the CLI exit unsuccessfully. |
| I19 | Join independently checks capacity, including under a test clock that moves backwards. |
| I20 | Retained opaque-record boundary: the server cannot inspect the encrypted record type. Pending places can post only one immutable bounded record; clients validate the authenticated schema. |
| I21 | Documented here: a matched invite can receive 410 for used/revoked/expired state; absent rooms and unmatched credentials receive 404. This intentionally informs a capability holder. |
| I22 | Destroy dialog opening and submission both require current client admission. A pending visitor cannot trigger a misleading local destruction flow through hidden controls. Server authorization remains mandatory. |
| I23 | Retained generic loss-of-access wording explicitly includes removal. A 404 alone cannot establish whether the room ended or just the member lost access. |
| I24 | Documented limitation: admitted members can decrypt retained encrypted roster history, including old invite labels. Revocation prevents future access; it cannot revoke ciphertext or keys already disclosed to a member. Invite labels should not contain information unsuitable for eventual admitted members. |
| I25 | Retained bounded shared-room availability: any admitted member can consume the record budget or destroy the room. The creator can remove members. |
| I26 | An all-filtered nonempty message now prompts the writer to use visible text. |
| I27 | Retained operator trust boundary: the checkout is executable deployment code and must be controlled by its operator. Local-change warnings do not sandbox a hostile checkout. |
| I28 | Release lookup requests now restrict redirect protocols, response size and duration consistently. |
| I29 | API errors use an allowlist of fixed application messages; arbitrary server-supplied text becomes HTTP status text. |
| I30 | Build start validates the selected version before invoking Compose; the frontend build already validates it. This is robustness hardening. There was no shell command execution in the reported path. |

The report's two retracted findings remain retracted: no build-argument command
execution and no Cloudflare-only client-IP spoofing bypass were established.
