"""ArchiMate reference model, requirement catalogue, and traceability checker.

Checker levels:
  structural  - the four catalogue links exist between the specified endpoint IDs (any type/direction)
  semantic    - each link also has the expected relationship type, direction, and endpoint element types
  conformance - for runtime requirements, evidence-satisfying events were emitted by the designated component
The semantic rules encode the expected type of each path position; they do not implement
the full ArchiMate 3.2 relationship table.
"""
import copy
import xml.etree.ElementTree as ET

NS = "http://www.opengroup.org/xsd/archimate/3.0/"
XSI = "http://www.w3.org/2001/XMLSchema-instance"

REQS = {
    "FR01": "Account attribution", "FR02": "Action identification", "FR03": "Object identification",
    "FR04": "Outcome recording", "FR05": "Time representation", "FR06": "Record linkage",
    "FR07": "Change provenance", "FR08": "Upload fingerprint", "FR09": "Denial visibility",
    "FR10": "Content integrity", "FR11": "Completeness checkpoint", "FR12": "Recomputed-chain detection",
    "FR13": "Export authorization", "FR14": "Retention eligibility", "FR15": "Data minimization",
    "FR16": "Verifiable export",
}
ELEMENTS = {
    "goal-attribution": ("Goal", "Attributable activity reconstruction"),
    "goal-integrity": ("Goal", "Verifiable evidence preservation"),
    "goal-handling": ("Goal", "Controlled evidence handling"),
    "IN01": ("BusinessProcess", "Identify account and action"),
    "IN02": ("BusinessProcess", "Correlate activity records"),
    "IN03": ("BusinessProcess", "Reconstruct changes"),
    "IN04": ("BusinessProcess", "Verify preservation"),
    "IN05": ("BusinessProcess", "Review evidence disclosure"),
    "app-web": ("ApplicationComponent", "Web application"),
    "app-db": ("ApplicationComponent", "Database access layer"),
    "app-export": ("ApplicationComponent", "Evidence export service"),
    "app-verifier": ("ApplicationComponent", "Integrity verifier"),
    "node-http": ("Node", "HTTP gateway node"),
    "node-anchor": ("Node", "Checkpoint store node"),
    "obj-evidence": ("DataObject", "Evidence event record"),
    "art-evidence-log": ("Artifact", "Evidence log file"),
}
for rid, name in REQS.items():
    ELEMENTS[rid] = ("Requirement", name)

# requirement -> (goal, designated element, evidence object, investigation purpose)
CATALOGUE = {
    "FR01": ("goal-attribution", "app-web", "obj-evidence", "IN01"),
    "FR02": ("goal-attribution", "app-web", "obj-evidence", "IN01"),
    "FR03": ("goal-attribution", "app-web", "obj-evidence", "IN01"),
    "FR04": ("goal-attribution", "app-web", "obj-evidence", "IN01"),
    "FR05": ("goal-attribution", "node-http", "obj-evidence", "IN02"),
    "FR06": ("goal-attribution", "node-http", "obj-evidence", "IN02"),
    "FR07": ("goal-attribution", "app-db", "obj-evidence", "IN03"),
    "FR08": ("goal-attribution", "app-web", "obj-evidence", "IN03"),
    "FR09": ("goal-attribution", "app-web", "obj-evidence", "IN02"),
    "FR10": ("goal-integrity", "app-verifier", "art-evidence-log", "IN04"),
    "FR11": ("goal-integrity", "node-anchor", "art-evidence-log", "IN04"),
    "FR12": ("goal-integrity", "node-anchor", "art-evidence-log", "IN04"),
    "FR13": ("goal-handling", "app-export", "obj-evidence", "IN05"),
    "FR14": ("goal-handling", "obj-evidence", "art-evidence-log", "IN05"),
    "FR15": ("goal-handling", "app-web", "obj-evidence", "IN05"),
    "FR16": ("goal-handling", "app-export", "obj-evidence", "IN04"),
}
# Same-type wrong assignments used for the consistent-misassignment fault class
MISASSIGN = {"app-web": "app-export", "node-http": "node-anchor", "app-db": "app-web",
             "app-verifier": "app-export", "node-anchor": "node-http", "app-export": "app-verifier",
             "obj-evidence": "art-evidence-log"}
# Requirements whose evidence is emitted at runtime with a component identifier
RUNTIME_REQS = {"FR01", "FR02", "FR03", "FR04", "FR05", "FR06", "FR07", "FR08", "FR09", "FR15"}

REALIZERS = {"ApplicationComponent", "Node", "DataObject", "Artifact"}


def build_model(catalogue=CATALOGUE):
    """Return (elements, relationships); relationships are dicts with id/type/source/target."""
    rels = []

    def add(rtype, src, tgt):
        if not any(r["type"] == rtype and r["source"] == src and r["target"] == tgt for r in rels):
            rels.append({"id": f"rel-{len(rels) + 1:03d}", "type": rtype, "source": src, "target": tgt})

    for req, (goal, comp, evid, inv) in catalogue.items():
        add("Realization", req, goal)
        add("Realization", comp, req)
        add("Association", comp, evid)
        add("Association", req, inv)
    structural = [
        ("Triggering", "IN01", "IN02"), ("Triggering", "IN02", "IN03"), ("Triggering", "IN03", "IN04"),
        ("Triggering", "IN04", "IN05"), ("Serving", "app-web", "IN01"), ("Serving", "node-http", "IN02"),
        ("Serving", "app-db", "IN03"), ("Serving", "app-verifier", "IN04"), ("Serving", "app-export", "IN05"),
        ("Assignment", "node-http", "art-evidence-log"), ("Realization", "art-evidence-log", "obj-evidence"),
        ("Flow", "app-web", "app-db"), ("Serving", "app-db", "app-export"), ("Serving", "app-verifier", "app-export"),
        ("Association", "node-http", "node-anchor"), ("Association", "goal-attribution", "goal-integrity"),
        ("Association", "goal-integrity", "goal-handling"),
    ]
    for t, s, g in structural:
        add(t, s, g)
    return copy.deepcopy(ELEMENTS), rels


def to_exchange_xml(elements, rels, path):
    ET.register_namespace("", NS)
    ET.register_namespace("xsi", XSI)
    root = ET.Element(f"{{{NS}}}model", {"identifier": "model-evidence-traceable-ea"})
    ET.SubElement(ET.SubElement(root, f"{{{NS}}}name"), "x")
    root[0].text = "Evidence traceable EA reference model"
    root[0].remove(root[0][0])
    els = ET.SubElement(root, f"{{{NS}}}elements")
    for eid, (etype, name) in elements.items():
        e = ET.SubElement(els, f"{{{NS}}}element", {"identifier": eid, f"{{{XSI}}}type": etype})
        ET.SubElement(e, f"{{{NS}}}name").text = name
    rs = ET.SubElement(root, f"{{{NS}}}relationships")
    for r in rels:
        ET.SubElement(rs, f"{{{NS}}}relationship", {"identifier": r["id"], "source": r["source"],
                                                     "target": r["target"], f"{{{XSI}}}type": r["type"]})
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def read_exchange_xml(path):
    root = ET.parse(path).getroot()
    elements = {e.get("identifier"): (e.get(f"{{{XSI}}}type"), e.findtext(f"{{{NS}}}name"))
                for e in root.iter(f"{{{NS}}}element")}
    rels = [{"id": r.get("identifier"), "type": r.get(f"{{{XSI}}}type"), "source": r.get("source"),
             "target": r.get("target")} for r in root.iter(f"{{{NS}}}relationship")]
    return elements, rels


# ---- checkers ------------------------------------------------------------------------

def _path_specs(req, entry):
    goal, comp, evid, inv = entry
    # (source, target, expected type, expected source types, expected target types)
    return [
        (req, goal, "Realization", {"Requirement"}, {"Goal"}),
        (comp, req, "Realization", REALIZERS, {"Requirement"}),
        (comp, evid, "Association", REALIZERS, {"DataObject", "Artifact"}),
        (req, inv, "Association", {"Requirement"}, {"BusinessProcess"}),
    ]


def structural_check(elements, rels, catalogue=CATALOGUE):
    """t_r = 1 when the four links exist between the specified endpoints (type and direction ignored)."""
    pairs = {frozenset((r["source"], r["target"])) for r in rels}
    result = {}
    for req, entry in catalogue.items():
        ok = all(s in elements and t in elements and frozenset((s, t)) in pairs
                 for s, t, *_ in _path_specs(req, entry))
        result[req] = ok
    return result


def semantic_check(elements, rels, catalogue=CATALOGUE):
    triples = {(r["type"], r["source"], r["target"]) for r in rels}
    result = {}
    for req, entry in catalogue.items():
        ok = True
        for s, t, rtype, stypes, ttypes in _path_specs(req, entry):
            if (rtype, s, t) not in triples or s not in elements or t not in elements:
                ok = False
            elif elements[s][0] not in stypes or elements[t][0] not in ttypes:
                ok = False
        result[req] = ok
    return result


def _evidence_events(req, events):
    """Events that carry the evidence a runtime requirement depends on."""
    if req in {"FR05", "FR06"}:
        return [e for e in events if e.get("source") == "gateway"]
    if req == "FR07":
        return [e for e in events if e.get("source") == "database"]
    if req == "FR08":
        return [e for e in events if "content_digest" in e]
    if req == "FR09":
        return [e for e in events if e.get("source") == "application" and e.get("outcome") == "denied"]
    return [e for e in events if e.get("source") == "application"]


def conformance_check(events, catalogue=CATALOGUE):
    """Runtime requirements: evidence events must come from the designated component.
    Non-runtime requirements return None (not checkable from event provenance)."""
    result = {}
    for req, (_, comp, _, _) in catalogue.items():
        if req not in RUNTIME_REQS:
            result[req] = None
            continue
        evs = _evidence_events(req, events)
        result[req] = bool(evs) and all(e.get("component") == comp for e in evs)
    return result


# ---- fault injection -------------------------------------------------------------------

def inject(fault, req):
    """Return (elements, rels, catalogue) with one fault affecting requirement `req`."""
    cat = copy.deepcopy(CATALOGUE)
    elements, rels = build_model(cat)
    goal, comp, evid, inv = cat[req]
    if fault == "missing_link":          # F1: investigation association removed
        rels = [r for r in rels if not (r["source"] == req and r["target"] == inv)]
    elif fault == "wrong_type":          # F2: component->requirement realization becomes association
        for r in rels:
            if r["source"] == comp and r["target"] == req:
                r["type"] = "Association"
    elif fault == "reversed":            # F3: requirement->goal realization reversed
        for r in rels:
            if r["source"] == req and r["target"] == goal and r["type"] == "Realization":
                r["source"], r["target"] = goal, req
    elif fault == "redirected":          # F4: investigation link points to another purpose
        others = [i for i in ["IN01", "IN02", "IN03", "IN04", "IN05"] if i != inv]
        for r in rels:
            if r["source"] == req and r["target"] == inv:
                r["target"] = others[0]
    elif fault == "misassigned":         # F5: catalogue and model consistently use a wrong same-family element
        cat[req] = (goal, MISASSIGN[comp], evid, inv)
        elements, rels = build_model(cat)
    return elements, rels, cat


FAULTS = ["missing_link", "wrong_type", "reversed", "redirected", "misassigned"]
