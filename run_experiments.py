"""Run every experiment reported in the revised manuscript and write results/*.json.

Usage: python run_experiments.py
"""
import json
import os
import random
import statistics
from collections import defaultdict
from datetime import datetime, timedelta

import integrity as I
import model_checker as M
from prototype import CONFIGS, SEEDS, PASSWORD_SENTINEL, TOKEN_SENTINEL, BODY_SENTINEL, run

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
QUESTIONS = ["account", "action", "object", "timestamp", "outcome", "linkage"]
PATH_ACTION = {"/documents/update": "update", "/documents/export": "export",
               "/documents/view": "view", "/documents/upload": "upload", "/login": "login"}
STATUS_OUTCOME = {200: "success", 401: "denied", 403: "denied"}


def parse_utc(ts):
    try:
        dt = datetime.fromisoformat(ts)
        return dt if dt.utcoffset() == timedelta(0) else None
    except (TypeError, ValueError):
        return None


# ---- context availability (Equation 4) ------------------------------------------------

def context_scores(config, events, truths):
    """Return {question: matched count} and per-activity matches."""
    per_q = defaultdict(int)
    per_act = defaultdict(lambda: [0, 0])
    if config == "access_only":
        # aligned by benchmark request sequence -> upper bound under supplied alignment
        pairs = [(t, [e]) for t, e in zip(truths, events)]
    else:
        by_rid = defaultdict(list)
        for e in events:
            by_rid[e.get("request_id")].append(e)
        pairs = [(t, by_rid.get(t["request_id"], [])) for t in truths]
    for t, evs in pairs:
        app = next((e for e in evs if e.get("source") == "application"), evs[0] if evs else {})
        start, end = parse_utc(t["t_start"]), parse_utc(t["t_end"])
        ts = parse_utc(app.get("ts"))
        action = app.get("action") or PATH_ACTION.get(app.get("path"))
        outcome = app.get("outcome") or STATUS_OUTCOME.get(app.get("status"))
        hits = {
            "account": app.get("account") == t["account"],
            "action": action == t["action"],
            "object": app.get("object") == t["object"],
            "timestamp": ts is not None and start <= ts <= end,
            "outcome": outcome == t["outcome"],
            "linkage": app.get("request_id") == t["request_id"],
        }
        for q, ok in hits.items():
            per_q[q] += ok
        per_act[t["activity"]][0] += sum(hits.values())
        per_act[t["activity"]][1] += 6
    return dict(per_q), {k: tuple(v) for k, v in per_act.items()}


# ---- manipulations (Table 6) --------------------------------------------------------------

def manipulate(envelopes, kind, rng):
    env = [dict(e, event=dict(e["event"])) for e in envelopes]
    n = len(env)
    if kind == "change_outcome":
        i = rng.choice([k for k, e in enumerate(env) if "outcome" in e["event"]])
        env[i]["event"]["outcome"] = "success" if env[i]["event"]["outcome"] == "denied" else "denied"
    elif kind == "delete_interior":
        del env[rng.randint(1, n - 2)]
    elif kind == "delete_final":
        env.pop()
    elif kind == "swap":
        i = rng.randint(0, n - 2)
        env[i], env[i + 1] = env[i + 1], env[i]
    elif kind == "modify_recompute":
        i = rng.choice([k for k, e in enumerate(env) if "outcome" in e["event"]])
        env[i]["event"]["outcome"] = "success" if env[i]["event"]["outcome"] == "denied" else "denied"
        env = I.seal([e["event"] for e in env])
    return env


MANIPULATIONS = ["change_outcome", "delete_interior", "delete_final", "swap", "modify_recompute"]


def verifier_for(config):
    cfg = CONFIGS[config]
    if not cfg["chain"]:
        return None
    if cfg["anchor"]:
        return lambda env, cp: I.verify_anchored(env, [cp])
    return lambda env, cp: I.verify_chain(env)


# ---- scoped predicates (Table 2, Equation 5) ---------------------------------------------

def predicates(config, events, truths, envelopes, checkpoint, rng):
    cfg = CONFIGS[config]
    app = [e for e in events if e.get("source") == "application"]
    detailed = app if cfg["structured"] else []
    q = {}
    q["FR01"] = bool(detailed) and all(e.get("account") for e in detailed)
    q["FR02"] = all(e.get("action") or e.get("path") for e in (app or events))
    q["FR03"] = bool(detailed) and all(e.get("object") for e in detailed)
    q["FR04"] = all(e.get("outcome") or e.get("status") for e in (app or events))
    q["FR05"] = all(parse_utc(e.get("ts")) for e in events)
    rid_counts = defaultdict(int)
    for e in events:
        if e.get("request_id"):
            rid_counts[e["request_id"]] += 1
    q["FR06"] = all(rid_counts.get(t["request_id"], 0) >= 2 for t in truths)
    db_rids = {e["request_id"] for e in events if e.get("source") == "database"
               and e.get("before_digest") and e.get("after_digest")}
    q["FR07"] = all(t["request_id"] in db_rids for t in truths if t["activity"] == "doc_update")
    up = {e["request_id"] for e in app if e.get("content_digest")}
    q["FR08"] = all(t["request_id"] in up for t in truths if t["activity"] == "upload")
    if cfg["structured"]:
        denied_acts = {t["activity"] for t in truths
                       if any(e.get("request_id") == t["request_id"] and e.get("outcome") == "denied" for e in app)}
    else:
        denied_acts = {t["activity"] for t, e in zip(truths, events) if e.get("status") in (401, 403)}
    q["FR09"] = {"login_fail", "doc_denied"} <= denied_acts
    verify = verifier_for(config)
    if verify:
        q["FR10"] = not verify(manipulate(envelopes, "change_outcome", rng), checkpoint)
        q["FR11"] = not verify(manipulate(envelopes, "delete_final", rng), checkpoint)
        q["FR12"] = not verify(manipulate(envelopes, "modify_recompute", rng), checkpoint)
    else:
        q["FR10"] = q["FR11"] = q["FR12"] = False
    if cfg["handling"]:
        try:
            I.export_evidence(envelopes, "viewer")
            viewer_denied = False
        except PermissionError:
            viewer_denied = True
        payload, manifest = I.export_evidence(envelopes, "investigator")
        q["FR13"] = viewer_denied
        q["FR14"] = I.retention_eligible(400, 365, False) and not I.retention_eligible(400, 365, True)
        q["FR16"] = I.verify_export(payload, manifest)
    else:
        q["FR13"] = q["FR14"] = q["FR16"] = False
    blob = json.dumps(events)
    q["FR15"] = not any(s in blob for s in (PASSWORD_SENTINEL, TOKEN_SENTINEL, BODY_SENTINEL))
    return q


def jsonl_bytes(items):
    return sum(len(I.canon(x)) + 1 for x in items)


def main():
    os.makedirs(OUT, exist_ok=True)
    res = {"per_seed": {}, "aggregate": {}, "manipulation": {}, "volume": {}, "per_activity": {}}
    agg = {c: dict(requests=0, events=0, ctx=0, ctx_total=0, preds=None) for c in CONFIGS}
    manip = {c: {k: 0 for k in MANIPULATIONS + ["untouched"]} for c in CONFIGS if CONFIGS[c]["chain"]}
    vol = defaultdict(lambda: defaultdict(list))
    per_act = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    structured_events_for_conformance = None

    for seed in SEEDS:
        order = list(CONFIGS)
        k = SEEDS.index(seed) % len(order)
        order = order[k:] + order[:k]  # rotate configuration order
        res["per_seed"][seed] = {}
        for config in order:
            events, truths, _ = run(config, seed)
            rng = random.Random(seed * 1000 + list(CONFIGS).index(config))
            envelopes = I.seal(events) if CONFIGS[config]["chain"] else []
            checkpoint = I.make_checkpoint(envelopes) if CONFIGS[config]["anchor"] else None
            perq, pact = context_scores(config, events, truths)
            preds = predicates(config, events, truths, envelopes, checkpoint, rng)
            ctx = sum(perq.values())
            a = agg[config]
            a["requests"] += len(truths)
            a["events"] += len(events)
            a["ctx"] += ctx
            a["ctx_total"] += 6 * len(truths)
            a["preds"] = preds if a["preds"] is None else {r: a["preds"][r] and v for r, v in preds.items()}
            for act, (h, t) in pact.items():
                per_act[config][act][0] += h
                per_act[config][act][1] += t
            res["per_seed"][seed][config] = {"context": f"{ctx}/{6 * len(truths)}",
                                             "scoped": f"{sum(preds.values())}/16",
                                             "per_question": perq}
            vol[config]["event_json"].append(jsonl_bytes(events))
            if envelopes:
                vol[config]["envelopes"].append(jsonl_bytes(envelopes))
                payload, manifest = I.export_evidence(envelopes, "investigator")
                vol[config]["manifest"].append(len(I.canon(manifest)))
                vol[config]["checkpoint"].append(len(I.canon(checkpoint)) if checkpoint else 0)
            verify = verifier_for(config)
            if verify:
                mrng = random.Random(seed)
                for kind in MANIPULATIONS:
                    manip[config][kind] += not verify(manipulate(envelopes, kind, mrng), checkpoint)
                manip[config]["untouched"] += verify(envelopes, checkpoint)
                res["per_seed"][seed][config]["detected"] = None
            if config == "structured" and structured_events_for_conformance is None:
                structured_events_for_conformance = events

    for config, a in agg.items():
        res["aggregate"][config] = {
            "requests": a["requests"], "events": a["events"],
            "context": f"{a['ctx']}/{a['ctx_total']}", "context_pct": round(100 * a["ctx"] / a["ctx_total"], 2),
            "scoped": f"{sum(a['preds'].values())}/16",
            "satisfied": sorted(r for r, v in a["preds"].items() if v),
            "complete_paths": "16/16" if CONFIGS[config]["mapped"] else "0/16",
        }
    res["manipulation"] = manip
    res["volume"] = {c: {k: statistics.median(v) for k, v in d.items()} for c, d in vol.items()}
    res["per_activity"] = {c: {a: f"{h}/{t}" for a, (h, t) in d.items()} for c, d in per_act.items()}

    # ---- traceability checker (Table 7) ----
    elements, rels = M.build_model()
    M.to_exchange_xml(elements, rels, os.path.join(OUT, "reference_model.xml"))
    elements, rels = M.read_exchange_xml(os.path.join(OUT, "reference_model.xml"))
    intact = {"elements": len(elements), "relationships": len(rels),
              "structural": sum(M.structural_check(elements, rels).values()),
              "semantic": sum(M.semantic_check(elements, rels).values()),
              "conformance": sum(bool(v) for v in M.conformance_check(structured_events_for_conformance).values()
                                 if v is not None)}
    faults = {}
    for fault in M.FAULTS:
        det = dict(structural=0, semantic=0, conformance=0, conformance_applicable=0, any=0)
        for req in M.REQS:
            el, rl, cat = M.inject(fault, req)
            s = not M.structural_check(el, rl, cat)[req]
            m = not M.semantic_check(el, rl, cat)[req]
            c = M.conformance_check(structured_events_for_conformance, cat)[req]
            cdet = c is not None and not c
            det["structural"] += s
            det["semantic"] += m
            det["conformance"] += cdet
            det["conformance_applicable"] += c is not None
            det["any"] += s or m or cdet
        faults[fault] = det
    res["checker"] = {"intact": intact, "faults": faults}

    # ---- preservation boundary tests (Table 8) ----
    boundary = defaultdict(lambda: [0, 0])
    exposures = []
    for seed in SEEDS:
        events, truths, _ = run("mapped_anchored", seed)
        env = I.seal(events)
        rng = random.Random(seed + 7)
        crash_at = rng.randint(120, len(env) - 30)          # process stops before the final checkpoint
        crashed = env[:crash_at]
        periodic = I.periodic_checkpoints(crashed, 20)
        # B1: crash, then delete the final 25 retained events
        tampered = crashed[:-25]
        boundary["b1_end_only"][0] += not I.verify_anchored(tampered, [], final=True)
        boundary["b1_periodic"][0] += not I.verify_anchored(tampered, periodic, final=False)
        # B2: delete only the events after the last periodic checkpoint
        last = periodic[-1]["count"]
        exposures.append(crash_at - last)
        tail_cut = crashed[:last] if crash_at > last else crashed[:-1]
        boundary["b2_tail_only"][0] += not I.verify_anchored(tail_cut, periodic, final=False)
        # B3: attacker holds key K, rewrites event and re-issues checkpoint
        forged = manipulate(env, "modify_recompute", rng)
        boundary["b3_key_compromise"][0] += not I.verify_anchored(forged, [I.make_checkpoint(forged)])
        # B4: compromised generator falsifies an outcome before sealing
        falsified = [dict(e) for e in events]
        idx = next(i for i, e in enumerate(falsified) if e.get("outcome") == "denied")
        falsified[idx]["outcome"] = "success"
        fenv = I.seal(falsified)
        boundary["b4_generator"][0] += not I.verify_anchored(fenv, [I.make_checkpoint(fenv)])
        # B5: crash between database commit and audit write
        ev5, tr5, app5 = run("mapped_anchored", seed, fault_skip_audit_on_update=rng.randint(1, 20))
        env5 = I.seal(ev5)
        boundary["b5_chain_verifier"][0] += not I.verify_anchored(env5, [I.make_checkpoint(env5)])
        db_updates = app5.db.execute("SELECT SUM(version - 1) FROM documents").fetchone()[0]
        change_events = sum(1 for e in ev5 if e.get("source") == "database")
        boundary["b5_reconciliation"][0] += db_updates != change_events
        for key in list(boundary):
            boundary[key][1] = SEEDS.index(seed) + 1
    res["boundary"] = {k: f"{d}/{t}" for k, (d, t) in boundary.items()}
    res["boundary_exposure_events"] = exposures

    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(res, f, indent=2, default=str)
    print(json.dumps({k: res[k] for k in ["aggregate", "manipulation", "volume", "checker", "boundary",
                                          "boundary_exposure_events"]}, indent=1, default=str))


if __name__ == "__main__":
    main()
