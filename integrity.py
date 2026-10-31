"""Hash-chain preservation, trusted checkpoints, and evidence-handling controls.

Equation (2): h_i = SHA-256(J({seq: i, prev_hash: h_{i-1}, event: e_i}))
Equation (3): tau = HMAC-SHA-256(K, J({count: N, head: h_N}))
"""
import hashlib
import hmac
import json

GENESIS = "0" * 64
# Public synthetic key: supports reproducibility, insecure for deployment.
SYNTHETIC_KEY = b"synthetic-checkpoint-key-not-for-production"


def canon(obj) -> bytes:
    """Canonical JSON: sorted keys, compact separators, UTF-8, no ASCII escaping."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal(events):
    """Wrap events in hash-chained envelopes."""
    envelopes, prev = [], GENESIS
    for i, ev in enumerate(events, start=1):
        digest = sha256_hex(canon({"seq": i, "prev_hash": prev, "event": ev}))
        envelopes.append({"seq": i, "prev_hash": prev, "event": ev, "digest": digest})
        prev = digest
    return envelopes


def make_checkpoint(envelopes, key=SYNTHETIC_KEY, count=None):
    n = len(envelopes) if count is None else count
    head = envelopes[n - 1]["digest"] if n else GENESIS
    tag = hmac.new(key, canon({"count": n, "head": head}), hashlib.sha256).hexdigest()
    return {"count": n, "head": head, "tag": tag}


def periodic_checkpoints(envelopes, interval, key=SYNTHETIC_KEY):
    return [make_checkpoint(envelopes, key, c) for c in range(interval, len(envelopes) + 1, interval)]


def verify_chain(envelopes):
    """Chain-only verification (unanchored)."""
    prev = GENESIS
    for i, env in enumerate(envelopes, start=1):
        if env.get("seq") != i or env.get("prev_hash") != prev:
            return False
        if sha256_hex(canon({"seq": i, "prev_hash": prev, "event": env["event"]})) != env.get("digest"):
            return False
        prev = env["digest"]
    return True


def verify_anchored(envelopes, checkpoints, key=SYNTHETIC_KEY, final=True):
    """Chain verification plus comparison with trusted checkpoint(s).

    final=True: the last checkpoint must equal the full log (end-of-workload checkpoint).
    final=False: periodic checkpoints; every checkpointed prefix must still be present.
    With no checkpoint, verification degrades to chain-only.
    """
    if not verify_chain(envelopes):
        return False
    for cp in checkpoints:
        expected = hmac.new(key, canon({"count": cp["count"], "head": cp["head"]}), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, cp["tag"]):
            return False
        if cp["count"] > len(envelopes) or envelopes[cp["count"] - 1]["digest"] != cp["head"]:
            return False
    if final and checkpoints and checkpoints[-1]["count"] != len(envelopes):
        return False
    return True


# ---- Evidence-handling controls (FR13, FR14, FR16) ----------------------------------

EXPORT_ROLES = {"investigator"}


def export_evidence(envelopes, role):
    """Role-checked export with a digest manifest (FR13, FR16)."""
    if role not in EXPORT_ROLES:
        raise PermissionError("role not authorised to export evidence")
    payload = b"\n".join(canon(e) for e in envelopes)
    manifest = {"records": len(envelopes), "sha256": sha256_hex(payload), "exported_by_role": role}
    return payload, manifest


def verify_export(payload, manifest):
    return sha256_hex(payload) == manifest["sha256"]


def retention_eligible(age_days, retention_days, on_hold):
    """True when evidence may be disposed of (FR14)."""
    return age_days > retention_days and not on_hold
