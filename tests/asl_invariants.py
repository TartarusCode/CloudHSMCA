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
  integration  every aws-sdk:<service>:<action> Parameters block only names
               fields that service model accepts — Step Functions rejects an
               unknown one at creation time (SCHEMA_VALIDATION_FAILED), which no
               amount of graph walking will tell you

usage: python3 tests/asl_invariants.py [module-dir]
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STACK = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(
    os.path.join(HERE, "..", "modules", "hsm-ca"))
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
    "verified_backup_param": "/corp-pki/pki/ceremony/verified_backup_id",
    "lease_table": "corp-pki-ceremony-lease",
    "bootstrap_enabled": True,
    "event_bus_name": "default",
    "ca_name": "corp-pki",
    "ca_bundle_ssm_pem": "/corp-pki/pki/ca_bundle.pem",
    "root_ca_ssm_pem": "/corp-pki/pki/root_ca.pem",
    "intermediate_ssm_pem": "/corp-pki/pki/intermediate_ca.pem",
    "cluster_id_out": "cluster-abc123",
    "kms_key_arn_out": "arn:aws:kms:us-west-2:111122223333:key/abc",
    "bucket_out": "corp-pki-pki-artifacts",
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


def render(vars_=None):
    body = render_template(TEMPLATE, dict(vars_ if vars_ is not None else RENDER_VARS))
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


def check_aws_sdk_parameters(states, check):
    """Step Functions validates aws-sdk integration parameters against the
    service model when the state machine is created, so a field the API does not
    have fails the whole state machine with SCHEMA_VALIDATION_FAILED. That is a
    live-apply failure with no offline signal unless the model is consulted."""
    try:
        import botocore.session
    except ImportError:
        print("  SKIP  aws-sdk parameters (botocore not installed; CI installs boto3)")
        return

    session = botocore.session.get_session()
    problems = []
    checked = 0
    checked = 0
    pattern = re.compile(r"^arn:aws:states:::aws-sdk:([a-z0-9-]+):([A-Za-z0-9]+)$")
    for name, state in states.items():
        match = pattern.match(state.get("Resource", ""))
        if not match:
            continue
        service, action = match.group(1), match.group(2)
        # Step Functions' own integration identifier is "sfn"; botocore calls
        # the service "stepfunctions".
        service_model_name = {"sfn": "stepfunctions"}.get(service, service)
        params = state.get("Parameters") or {}
        keys = [key[:-2] if key.endswith(".$") else key for key in params]
        try:
            model = session.get_service_model(service_model_name)
            operation = model.operation_model(action[0].upper() + action[1:])
        except Exception as exc:  # noqa: BLE001 - the message is the finding
            problems.append("%s: %s:%s is not in the botocore model (%s)"
                            % (name, service, action, exc))
            continue
        allowed = set((operation.input_shape.members or {}) if operation.input_shape else {})
        unknown = sorted(key for key in keys if key not in allowed)
        if unknown:
            problems.append("%s: %s:%s does not accept %s (accepts %s)"
                            % (name, service, action, unknown, sorted(allowed)))
        checked += 1

    check(not problems,
          "%d aws-sdk operations expose only fields the service accepts" % checked,
          "; ".join(problems))


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

    print()
    print("aws-sdk integration parameters:")
    check_aws_sdk_parameters(states, check)

    # A list of strings is a literal: Step Functions interpolates a path only
    # when the *key* ends in `.$`, so `"InstanceIds": ["$.host..."]` sends the
    # text "$.host..." to EC2/SSM. That fails at run time and passes every
    # structural check, so the shape is asserted rather than the intent.
    def literal_paths(node, where=""):
        hits = []
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, list) and any(
                        isinstance(item, str) and item.startswith("$.") for item in value):
                    hits.append("%s/%s" % (where, key))
                hits += literal_paths(value, "%s/%s" % (where, key))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                hits += literal_paths(item, "%s[%d]" % (where, index))
        return hits

    buried = literal_paths(defn)
    check(not buried, "no JSONPath hides inside a list (it would be sent literally)",
          str(buried))

    instance_calls = [n for n, s in states.items()
                      if s.get("Resource", "").endswith(
                          (":ssm:sendCommand", ":ssm:describeInstanceInformation",
                           ":ec2:terminateInstances"))]
    unresolved_ids = [n for n in instance_calls
                      if "States.Array($.host.Instances[0].InstanceId)"
                      not in json.dumps(states[n])]
    check(bool(instance_calls), "the ceremony drives the host through EC2/SSM",
          str(instance_calls))
    check(not unresolved_ids,
          "every EC2/SSM call resolves the instance id with States.Array",
          str(unresolved_ids))

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
    # The success-path lease release is deliberately best-effort: its Catch
    # rejoins the teardown path so a DynamoDB hiccup cannot discard a completed
    # ceremony whose root is already escrowed.
    catters = [(n, c["Next"]) for n, s in states.items() for c in s.get("Catch", [])
               if n != "ReleaseClusterLease"]
    dead_ends = [n for n, target in catters
                 if not path_exists(defn, target, lambda x, s: s.get("Type") in FAIL_TYPES)]
    check(not dead_ends, "every Catch path ends in a Fail state", str(dead_ends))

    print("\ncluster lease (one owner per cluster, reclaimed when the owner ends):")
    acquire = states.get("AcquireClusterLease", {})
    check(acquire.get("Resource", "").endswith(":dynamodb:putItem"),
          "the lease is taken with a conditional DynamoDB write")
    check("ConditionExpression" in acquire.get("Parameters", {}) and
          "attribute_not_exists(lease_id)" in acquire.get("Parameters", {}).get("ConditionExpression", ""),
          "the acquire is conditional, so a second run cannot overwrite the lease")
    check("$$.Execution.Id" in json.dumps(acquire),
          "the lease is owned by the execution, not by a shared name")
    release = [n for n, s in states.items()
               if n.startswith("Release") and s.get("Resource", "").endswith(":dynamodb:deleteItem")]
    check(len(release) >= 2, "the lease is released on both success and failure", str(release))
    check(path_exists(defn, "IsLeaseStale", lambda n, s: n == "StealClusterLease"),
          "a stale lease is reclaimed instead of blocking the cluster")
    check(path_exists(defn, "DescribeLeaseExecution", lambda n, s: n == "FailClusterBusy"),
          "a live lease owner refuses a concurrent run")

    # The original cause must survive cleanup. A Task records it in its Catch;
    # a guard/recorder Pass states it in Result. Either way the terminal Fail
    # reads the same $.error object.
    cleanup_tasks = set(delete_hsm + terminate)
    into_cleanup = [n for n, s in states.items()
                    if n not in cleanup_tasks and not n.startswith("Cleanup")
                    and any(t in (cleanup_entry, "CleanupHostOnFailure")
                            for _, t in edges(s))]
    losers = [n for n in into_cleanup
              if not (any(c.get("ResultPath") == "$.error"
                          for c in states[n].get("Catch", []))
                      or states[n].get("ResultPath") == "$.error")]
    check(not losers, "every failure route into cleanup preserves $.error", str(losers))
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
    # CreateHsm accepts ClusterId, AvailabilityZone and IpAddress — nothing else.
    # A backup is not a parameter: CloudHSM restores the cluster's most recent
    # backup onto a new HSM by itself, which is why the READY gate before the
    # rotation call is the thing that makes the restore predictable.
    stray = [n for n in hsm_creates
             if set(states[n].get("Parameters", {})) - {"ClusterId", "AvailabilityZone"}]
    check(not stray, "every CreateHsm passes only ClusterId and AvailabilityZone", str(stray))
    check(len(hsm_creates) >= 2, "bootstrap and rotation each create an HSM",
          str(hsm_creates))

    mode_choice = [n for n, s in states.items()
                   if s.get("Type") == "Choice" and "$.mode" in json.dumps(s)]
    check(bool(mode_choice), "an explicit $.mode input is honoured", str(mode_choice))
    inferred = "UNINITIALIZED" in json.dumps(states.get("ChooseMode", {}))
    check(inferred, "the cluster state is used when no mode is supplied")
    check("RecordInvalidMode" in states, "an unknown mode is refused, not guessed")

    ready_gate = [n for n, s in states.items()
                  if "Backups[0].BackupState" in json.dumps(s) and "READY" in json.dumps(s)]
    check(len(ready_gate) >= 2, "BackupState READY gates both restore and completion",
          str(ready_gate))
    stale = [n for n, s in states.items()
             if "Backups[0].State" in json.dumps(s)]
    check(not stale, "no gate reads the nonexistent Backups[0].State field", str(stale))
    check(path_exists(defn, "RequireReadyBackupRequested",
                      lambda n, s: n == "CreateHsmFromBackup"),
          "the READY backup gate precedes the rotation HSM")

    # Poll counters are workflow variables: a workflow variable is referenced as
    # `$name`, and an expression-valued Assign needs the `.$` suffix. Without
    # both, the counter is a literal string and every bounded loop is unbounded.
    increments = [n for n, s in states.items() if n.startswith("Increment")]
    wrong = []
    for name in increments:
        assign = states[name].get("Assign", {})
        if not any(k.endswith(".$") and v.startswith("States.MathAdd($")
                   for k, v in assign.items()):
            wrong.append(name)
    check(len(increments) >= 5 and not wrong,
          "every poll increment uses a workflow variable with a .$ expression", str(wrong))
    guards = [n for n, s in states.items() if n.startswith("Guard") and s.get("Type") == "Choice"]
    bad_guard = [n for n in guards
                 if any(r.get("Variable", "").startswith("$.")
                        for r in states[n].get("Choices", []))]
    check(not bad_guard, "poll guards read workflow variables, not payload counters", str(bad_guard))
    state_reads = [n for n, s in states.items()
                   if "$.hsmPoll" in json.dumps(s) or "$.commandPoll" in json.dumps(s)]
    check(not state_reads, "poll counters no longer share a path with API results", str(state_reads))

    # The escrow check must see a backup created by this run, and commit its id
    # before the chain can be announced.
    escrow = states.get("IsBackupReady", {})
    check("StringNotEqualsPath" in json.dumps(escrow),
          "the escrow gate rejects a pre-existing backup")
    check(path_exists(defn, "IsBackupReady",
                      lambda n, s: s.get("Resource", "").endswith(":ssm:putParameter")),
          "the verified backup id is committed before success")
    check(path_exists(defn, "RecordVerifiedBackup",
                      lambda n, s: n == "TerminateHostAfterSuccess"),
          "the escrow id is recorded before the host is terminated")

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
        # Either the terminate task itself, or the fan-out publish that only runs
        # after it (asserted in the fan-out section below).
        check(all(states[n].get("Resource", "").endswith(":ec2:terminateInstances")
                  or n == "PublishCaReadyEvent"
                  for n in inbound),
              "%s is reached only after the host is terminated" % terminal, str(inbound))
    hsms_gone = [n for n, s in states.items()
                 if "Hsms[0].HsmId" in json.dumps(s) and '"IsPresent": false' in json.dumps(s)]
    check(bool(hsms_gone), "a poll confirms the HSM is gone before success", str(hsms_gone))

    # --- 5. the fan-out ------------------------------------------------
    # The module is workload-agnostic: it announces the published chain and
    # knows nothing about who consumes it. A success that stops before the event
    # leaves every consumer waiting forever, and any rolesanywhere reference here
    # would mean the core module grew a workload dependency again.
    print("\nfan-out (publish the chain, know nothing about consumers):")
    check("PublishCaReadyEvent" in states, "PublishCaReadyEvent exists")
    check("rolesanywhere" not in json.dumps(defn),
          "the state machine has no rolesanywhere coupling")

    if "PublishCaReadyEvent" in states:
        publish = states["PublishCaReadyEvent"]
        resource = publish.get("Resource", "")
        # The optimized integration, not the aws-sdk one: it accepts Detail as an
        # object and raises EventBridge.FailedEntry, where aws-sdk:eventbridge
        # needs a pre-serialized string and returns 200 with FailedEntryCount=1
        # when AWS drops the event.
        check(resource == "arn:aws:states:::events:putEvents",
              "PublishCaReadyEvent uses the optimized events:putEvents integration", resource)
        entries = publish.get("Parameters", {}).get("Entries", [{}])
        entry = entries[0] if entries else {}
        check(entry.get("Source") == "cloudhsmca.pki",
              "the event source is cloudhsmca.pki", entry.get("Source"))
        check(entry.get("DetailType") == "CAChainPublished",
              "the detail type is CAChainPublished", entry.get("DetailType"))
        check(entry.get("EventBusName") == "default",
              "the event goes to the configured bus", entry.get("EventBusName"))

        detail = entry.get("Detail")
        check(isinstance(detail, dict),
              "Detail is a native object, not a pre-serialized string",
              type(detail).__name__)
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except ValueError:
                detail = {}
        detail = detail if isinstance(detail, dict) else {}
        missing = [k for k in ("ca_name", "cluster_id", "intermediate_kms_key_arn",
                               "ca_bundle_ssm_param", "root_ca_ssm_param",
                               "intermediate_ca_ssm_param", "verified_backup_ssm_param",
                               "artifacts_bucket")
                   if k not in detail]
        check(not missing, "the detail carries the whole contract", str(missing))
        check("verified_backup_id.$" in detail or "verified_backup_id" in detail,
              "the detail carries the verified escrow backup id", str(sorted(detail)))
        check(detail.get("ca_name") == "corp-pki",
              "the detail names the CA (consumers match on it)", str(detail.get("ca_name")))
        check(detail.get("artifacts_bucket") == "corp-pki-pki-artifacts",
              "the detail carries the bucket", str(detail.get("artifacts_bucket")))

        retried = [e for r in publish.get("Retry", []) for e in r.get("ErrorEquals", [])]
        check("EventBridge.FailedEntry" in retried,
              "a dropped event is retried, not silently accepted", str(retried))
        # The failure lands here, after teardown: routing to cleanup would delete
        # an already-deleted HSM and terminate an already-terminated host.
        catch_targets = [c.get("Next") for c in publish.get("Catch", [])]
        check(catch_targets == ["FailCaEventPublish"],
              "a failed publish goes to its own Fail, not through cleanup",
              str(catch_targets))
        check(states.get("FailCaEventPublish", {}).get("Type") == "Fail",
              "FailCaEventPublish is a Fail state")

        # The event must be the last Thing To Happen: HSM gone, backup READY,
        # host terminated — otherwise a consumer activates against a chain whose
        # Root key is not yet escrowed.
        check(path_exists(defn, "TerminateHostAfterSuccess",
                          lambda n, s: n == "PublishCaReadyEvent"),
              "the event is published after the host is terminated")
        check(path_exists(defn, "PublishCaReadyEvent",
                          lambda n, s: s.get("Type") == "Succeed"),
              "PublishCaReadyEvent precedes the Succeed state")
        check(bool(publish.get("Catch")),
              "a failed publish is caught instead of stalling")

    # --- 6. rotation-only rendering ---------------------------------------
    # enable_bootstrap = false must produce a valid, fully reachable definition
    # with no bootstrap states and no unresolved ${bootstrap_key}.
    print("\nrotation-only rendering (enable_bootstrap = false):")
    rot_vars = dict(RENDER_VARS, bootstrap_enabled=False)
    try:
        rot = render(rot_vars)
        rs = rot["States"]
        orphan = [n for n in ("SetBootstrapMode", "CreateHsmNoBackup", "RunBootstrapCeremony")
                  if n in rs]
        check(not orphan, "bootstrap states are rendered out", str(orphan))
        check("${bootstrap_key}" not in json.dumps(rot),
              "no unresolved bootstrap key remains")
        unreachable_rot = set(rs) - reachable(rot)
        check(not unreachable_rot, "every remaining state is reachable",
              str(sorted(unreachable_rot)))
        empty_choices = [n for n, s in rs.items()
                         if s.get("Type") == "Choice" and not s.get("Choices")]
        check(not empty_choices, "no Choice state has an empty Choices array",
              str(empty_choices))
        check(path_exists(rot, "ChooseCeremonyScript", lambda n, s: n == "RunRotationCeremony"),
              "rotation-only runs the rotation ceremony")
    except SystemExit as exc:
        check(False, "the rotation-only definition renders", str(exc))

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
