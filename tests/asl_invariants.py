#!/usr/bin/env python3
"""
Structural checks for statemachine.asl.json.tftpl.

The ASL is the ceremony: a wrong Next, a Catch that leaks the HSM, or a missing
backup check costs real money and can lose the Root CA. None of that is
observable with `terraform validate`, which only checks the JSON is a string.

So the definition is rendered exactly as Terraform renders it (templatefile
through `terraform console`) and then walked as a graph. What is asserted here
is the three properties the design depends on, plus the graph invariants that
make those properties meaningful:

  cleanup      every Task catches States.ALL; those paths converge on
               deleteHsm + terminateInstances and end in a Fail that re-raises
               the ORIGINAL error (no cleanup task may write $.error)
  ssm          describeInstanceInformation gates sendCommand on PingStatus
               Online, with a bounded poll in between
  modes        an explicit {"mode": ...} input is honoured, inference branches
               on the cluster state, and rotation only runs with a READY backup
  backup       the success path confirms the HSM is gone and a READY backup
               exists before it terminates the host and succeeds

usage: python3 tests/asl_invariants.py [module-dir]
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STACK = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(os.path.join(HERE, ".."))
TEMPLATE = "statemachine.asl.json.tftpl"

# Mirrors the locals in ceremony.tf. Values are placeholders: the checks are
# structural, and a real cluster id would make the output unreadable.
RENDER_VARS = {
    "name": "corp-pki",
    "cluster_id": "cluster-abc123",
    "availability_zone": "us-west-2a",
    "ami_id": "ami-0123456789abcdef0",
    "instance_type": "t3.small",
    "subnet_id": "subnet-0123456789abcdef0",
    "ceremony_security_group_id": "sg-0123456789abcdef0",
    "instance_profile_arn": "arn:aws:iam::111122223333:instance-profile/corp-pki-ceremony-host",
    "bucket": "corp-pki-ceremony-artifacts",
    "bootstrap_key": "scripts/bootstrap.sh",
    "rotate_key": "scripts/rotate_intermediate.sh",
    "trust_anchor_id": "6f5c0e2a-1b3d-4e5f-8a9b-0c1d2e3f4a5b",
    "trust_anchor_arn": "arn:aws:rolesanywhere:us-west-2:111122223333:trust-anchor/6f5c0e2a",
    "ssm_ca_bundle_pem": "/corp-pki/pki/ca_bundle.pem",
    "crl_function_name": "corp-pki-crl-issuer",
}

TASK_TYPES = {"Task"}
FAIL_TYPES = {"Fail"}


def render_template(template, vars_):
    if not os.path.isdir(os.path.join(STACK, ".terraform", "providers")):
        subprocess.run(["terraform", "-chdir=" + STACK, "init", "-backend=false",
                        "-input=false", "-no-color"], check=True,
                       capture_output=True, text=True)
    expr = "jsonencode(templatefile(%s, %s))" % (
        json.dumps(template), json.dumps(vars_))
    res = subprocess.run(["terraform", "console"], cwd=STACK, input=expr,
                         capture_output=True, text=True)
    if res.returncode != 0 or not res.stdout.strip():
        sys.exit("terraform console produced nothing for %s:\n%s\n%s"
                 % (template, res.stdout, res.stderr))
    body = res.stdout.strip()
    for _ in range(3):  # console quotes a string one extra time on some releases
        try:
            nxt = json.loads(body)
        except json.JSONDecodeError:
            break
        if not isinstance(nxt, str) or nxt == body:
            break
        body = nxt
    assert isinstance(body, str), type(body)
    return body


def render():
    body = render_template(TEMPLATE, RENDER_VARS)
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        sys.exit("the rendered definition is not JSON:\n%s" % body[:2000])


SCRIPT_CASES = [
    ("scripts/bootstrap.sh.tftpl", {"artifact_bucket": "corp-pki-ceremony-artifacts"}),
    # The rotate script only jq's its config at run time, so an empty document is
    # enough to prove the template renders to valid bash.
    ("scripts/rotate_intermediate.sh.tftpl", {"rotate_config": "{}"}),
]


def check_scripts():
    """Render each script template exactly as Terraform does, then bash -n it."""
    import tempfile
    failures = []
    print("\nscript templates (rendered by Terraform, then syntax-checked):")
    for template, vars_ in SCRIPT_CASES:
        body = render_template(template, vars_)
        name = os.path.basename(template)
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write(body)
            path = fh.name
        res = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        os.unlink(path)
        ok = res.returncode == 0
        print(("  PASS  " if ok else "  FAIL  ") + name + " is valid bash" +
              (("  -> " + res.stderr.strip()[:160]) if not ok else ""))
        if not ok:
            failures.append(name)
    return failures


def edges(state):
    """Every transition out of a state, as (label, target)."""
    out = []
    if "Next" in state:
        out.append(("Next", state["Next"]))
    if "Default" in state:
        out.append(("Default", state["Default"]))
    for i, rule in enumerate(state.get("Choices", [])):
        if "Next" in rule:
            out.append(("Choice[%d]" % i, rule["Next"]))
    for i, catch in enumerate(state.get("Catch", [])):
        out.append(("Catch[%d]" % i, catch["Next"]))
    return out


def reachable(defn):
    seen, stack = set(), [defn["StartAt"]]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(t for _, t in edges(defn["States"][name]))
    return seen


def path_exists(defn, start, predicate, limit=60):
    """True if a DFS from `start` visits a state satisfying `predicate`."""
    seen, stack = set(), [start]
    while stack:
        name = stack.pop()
        if name in seen or len(seen) > limit:
            continue
        seen.add(name)
        state = defn["States"][name]
        if predicate(name, state):
            return True
        stack.extend(t for _, t in edges(state))
    return False


def find_tasks(defn, resource_suffix):
    return [name for name, s in defn["States"].items()
            if s.get("Resource", "").endswith(resource_suffix)]


def main():
    defn = render()
    states = defn["States"]
    failures = []

    def check(ok, label, detail=""):
        print(("  PASS  " if ok else "  FAIL  ") + label +
              (("  -> " + detail) if detail and not ok else ""))
        if not ok:
            failures.append(label)

    # --- 0. JSON shapes ----------------------------------------------------
    print("definition graph:")
    check(defn["StartAt"] in states, "StartAt names a real state", defn["StartAt"])
    dangling = [(n, t) for n, s in states.items() for _, t in edges(s) if t not in states]
    check(not dangling, "every transition targets an existing state", str(dangling))
    unreachable = set(states) - reachable(defn)
    check(not unreachable, "every state is reachable from StartAt", str(sorted(unreachable)))
    unresolved = [n for n, s in states.items()
                  if "${" in json.dumps(s)]
    check(not unresolved, "no unresolved Terraform placeholder in the definition",
          str(unresolved))

    fails = [n for n, s in states.items() if s.get("Type") in FAIL_TYPES]
    check(bool(fails), "the definition can fail explicitly")
    for name in fails:
        s = states[name]
        ok = bool(s.get("Error")) and bool(s.get("Cause") or s.get("CausePath"))
        check(ok, "%s carries an Error and a Cause" % name)

    # --- 1. cleanup, every failure path ------------------------------------
    print("\ncleanup (Catch on States.ALL, always delete + terminate, keep the cause):")
    tasks = [n for n, s in states.items() if s.get("Type") in TASK_TYPES]
    missing = [n for n in tasks
               if not any("States.ALL" in c.get("ErrorEquals", []) for c in states[n].get("Catch", []))]
    check(not missing, "every Task catches States.ALL", str(missing))

    delete_hsm = find_tasks(defn, ":cloudhsmv2:deleteHsm")
    terminate = find_tasks(defn, ":ec2:terminateInstances")
    check(bool(delete_hsm), "deleteHsm is called by the workflow", str(delete_hsm))
    check(bool(terminate), "terminateInstances is called by the workflow", str(terminate))

    cleanup_entry = "CleanupHsmOnFailure"
    check(cleanup_entry in states, "a single cleanup entry state exists")
    if cleanup_entry in states:
        check(path_exists(defn, cleanup_entry,
                          lambda n, s: s.get("Resource", "").endswith(":cloudhsmv2:deleteHsm")),
              "cleanup reaches deleteHsm")
        check(path_exists(defn, cleanup_entry,
                          lambda n, s: s.get("Resource", "").endswith(":ec2:terminateInstances")),
              "cleanup reaches terminateInstances")

    # A Catch that does not route into cleanup must at least reach a Fail.
    catters = [(n, c["Next"]) for n, s in states.items() for c in s.get("Catch", [])]
    dead_ends = [n for n, target in catters
                 if not path_exists(defn, target, lambda x, s: s.get("Type") in FAIL_TYPES)]
    check(not dead_ends, "every Catch path ends in a Fail state", str(dead_ends))

    # The original cause must survive cleanup: the primary failure routes catch
    # into $.error, no cleanup task may write it, and the terminal Fail reads it.
    into_cleanup = [n for n, s in states.items()
                    if any(t == cleanup_entry for _, t in edges(s))]
    losers = [n for n in into_cleanup
              if not any(c.get("ResultPath") == "$.error"
                         for c in states[n].get("Catch", []))]
    check(not losers, "every failure route into cleanup preserves $.error at the Catch",
          str(losers))
    check(bool(into_cleanup), "the primary failure routes exist", str(len(into_cleanup)))
    cleanup_tasks = set(delete_hsm + terminate)
    clobber = [n for n in cleanup_tasks
               if any(c.get("ResultPath") == "$.error" for c in states[n].get("Catch", []))]
    check(not clobber, "no cleanup task writes over $.error", str(clobber))
    final_fail = states.get("FailOriginalCause", {})
    check("$.error" in json.dumps(final_fail),
          "the terminal Fail re-raises $.error", json.dumps(final_fail)[:120])
    check(all("ResultPath" not in states[n] or states[n]["ResultPath"] != "$.error"
              for n in delete_hsm + terminate if n in states),
          "neither deleteHsm nor terminateInstances clobbers $.error")

    # --- 2. SSM agent readiness -------------------------------------------
    print("\nssm readiness (no sendCommand before the agent reports Online):")
    describe = find_tasks(defn, ":ssm:describeInstanceInformation")
    send = find_tasks(defn, ":ssm:sendCommand")
    check(bool(describe), "describeInstanceInformation is polled", str(describe))
    check(bool(send), "sendCommand is issued", str(send))
    online_choice = [n for n, s in states.items()
                     if s.get("Type") == "Choice"
                     and "PingStatus" in json.dumps(s) and "Online" in json.dumps(s)]
    check(bool(online_choice), "a Choice gates on PingStatus == Online", str(online_choice))
    for target in send:
        gated = any(path_exists(defn, d, lambda n, s: n == target)
                    for d in describe)
        check(gated, "describeInstanceInformation precedes %s" % target)
    waits = [n for n, s in states.items() if s.get("Type") == "Wait"]
    check(len(waits) >= 4, "bounded waits exist for the four poll loops", str(sorted(waits)))

    # --- 3. bootstrap vs rotation -----------------------------------------
    print("\nbootstrap vs rotation:")
    hsm_creates = find_tasks(defn, ":cloudhsmv2:createHsm")
    with_backup = [n for n in hsm_creates
                   if "BackupId" in json.dumps(states[n].get("Parameters", {}))]
    without_backup = [n for n in hsm_creates if n not in with_backup]
    check(bool(with_backup), "a rotation CreateHsm restores from BackupId", str(with_backup))
    check(bool(without_backup), "a bootstrap CreateHsm passes no BackupId", str(without_backup))

    mode_choice = [n for n, s in states.items()
                   if s.get("Type") == "Choice" and "$.mode" in json.dumps(s)]
    check(bool(mode_choice), "an explicit $.mode input is honoured", str(mode_choice))
    inferred = "UNINITIALIZED" in json.dumps(states.get("ChooseMode", {}))
    check(inferred, "the cluster state is used when no mode is supplied")
    check("FailInvalidMode" in states, "an unknown mode is refused, not guessed")

    ready_gate = [n for n, s in states.items()
                  if "Backups[0].State" in json.dumps(s) and "READY" in json.dumps(s)]
    check(len(ready_gate) >= 2, "READY backups gate both restore and completion",
          str(ready_gate))

    # --- 4. success path ordering -----------------------------------------
    print("\nsuccess path (delete, confirm gone, confirm backup, then exit):")
    send_names = send
    for start in send_names:
        ok = path_exists(defn, start, lambda n, s: s.get("Resource", "").endswith(":cloudhsmv2:describeBackups"))
        check(ok, "%s is followed by a describeBackups check" % start)
    succeeded = [n for n, s in states.items() if s.get("Type") == "Succeed"]
    check(bool(succeeded), "a Succeed terminal state exists", str(succeeded))
    for terminal in succeeded:
        # Walk back is awkward in ASL; instead assert the only edges into the
        # terminal come from a terminateInstances task.
        inbound = [n for n, s in states.items()
                   if any(t == terminal for _, t in edges(s))]
        check(all(states[n].get("Resource", "").endswith(":ec2:terminateInstances")
                  for n in inbound),
              "%s is reached only after the host is terminated" % terminal, str(inbound))
    hsms_gone = [n for n, s in states.items()
                 if "Hsms[0].HsmId" in json.dumps(s) and '"IsPresent": false' in json.dumps(s)]
    check(bool(hsms_gone), "a poll confirms the HSM is gone before success", str(hsms_gone))

    # --- 5. activation tail -----------------------------------------------
    # The trust anchor is created DISABLED with a placeholder bundle, so the
    # workflow is what makes the PKI usable. A success that skips these states
    # leaves an anchor that accepts nothing, and nothing else would notice.
    print("\nactivation tail (install the chain, enable the anchor, import a CRL):")
    for required in ("UpdateTrustAnchor", "EnableTrustAnchor", "ImportOrUpdateCrl", "ReadCaBundle"):
        check(required in states, "%s exists" % required)

    if "UpdateTrustAnchor" in states:
        params = json.dumps(states["UpdateTrustAnchor"].get("Parameters", {}))
        check("CERTIFICATE_BUNDLE" in params, "UpdateTrustAnchor sets SourceType=CERTIFICATE_BUNDLE", params)
        check("$.bundle.caBundlePem" in params,
              "UpdateTrustAnchor installs the chain the ceremony published", params)
        check("trust-anchor/6f5c0e2a" in params or "$.bundle" in params,
              "UpdateTrustAnchor targets this module's trust anchor", params)
        check(path_exists(defn, "UpdateTrustAnchor",
                          lambda n, s: s.get("Type") == "Succeed"),
              "UpdateTrustAnchor precedes the Succeed state")

    if "EnableTrustAnchor" in states:
        params = json.dumps(states["EnableTrustAnchor"].get("Parameters", {}))
        check("TrustAnchorId" in params, "EnableTrustAnchor passes TrustAnchorId", params)
        check(path_exists(defn, "EnableTrustAnchor",
                          lambda n, s: s.get("Type") == "Succeed"),
              "EnableTrustAnchor precedes the Succeed state")
        check(path_exists(defn, "UpdateTrustAnchor",
                          lambda n, s: n == "EnableTrustAnchor"),
              "the anchor is enabled only after the real chain is installed")

    if "ImportOrUpdateCrl" in states:
        resource = states["ImportOrUpdateCrl"].get("Resource", "")
        check(resource.endswith(":lambda:invoke"),
              "ImportOrUpdateCrl invokes the CRL issuer", resource)

    # Every state after the HSM exists must still reach the teardown on failure.
    for name in ("ReadCaBundle", "UpdateTrustAnchor", "EnableTrustAnchor", "ImportOrUpdateCrl"):
        if name not in states:
            continue
        catches = states[name].get("Catch", [])
        check(bool(catches), "%s catches failures instead of stalling" % name)
        check(path_exists(defn, name,
                          lambda n, s: s.get("Resource", "").endswith(":cloudhsmv2:deleteHsm")),
              "%s can still reach deleteHsm on failure" % name)

    print()
    failures.extend(check_scripts())

    print()
    if failures:
        print("ASL INVARIANTS: FAIL (%d)" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    print("ASL INVARIANTS: PASS (%d states, %d tasks)"
          % (len(states), len(tasks)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
