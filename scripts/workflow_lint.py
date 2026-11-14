#!/usr/bin/env python3
"""
Validate the GitHub Actions definitions in this repository.

Two layers, because they catch different things:

  1. structural invariants a workflow can silently drift out of
       - every workflow declares top-level `permissions` (least privilege, made
         explicit rather than inherited from the repository default)
       - every job declares `timeout-minutes` (the default is 360 minutes, so a
         hung subprocess costs six hours of runner time)
       - every `run:` step in a composite action declares `shell` (the default
         shell differs between bash and sh, and only `shell: bash` gets
         `-eo pipefail`)
  2. `actionlint`, which knows the actual expression grammar, event payloads and
     action input schemas

usage:
  python3 scripts/workflow_lint.py [repo-root]
  python3 scripts/workflow_lint.py --no-yaml     # exercise the stdlib fallback

Exit codes: 0 clean (or actionlint absent outside CI), 1 problems, so this can be
a make prerequisite.
"""
import os
import re
import shutil
import subprocess
import sys

WORKFLOW_GLOBS = (".github/workflows",)
ACTIONS_DIR = ".github/actions"


def rel(root, path):
    return os.path.relpath(path, root)


# --------------------------------------------------------------------------- #
# collection
# --------------------------------------------------------------------------- #

def iter_files(root, directory, filename_re):
    base = os.path.join(root, directory)
    if not os.path.isdir(base):
        return
    for dirpath, _dirnames, filenames in os.walk(base):
        for name in sorted(filenames):
            if filename_re.match(name):
                yield os.path.join(dirpath, name)


def collect(root):
    wf = re.compile(r"^.*\.ya?ml$")
    workflows = []
    for directory in WORKFLOW_GLOBS:
        workflows.extend(iter_files(root, directory, wf))
    actions = list(iter_files(root, ACTIONS_DIR, re.compile(r"^action\.ya?ml$")))
    return workflows, actions


# --------------------------------------------------------------------------- #
# PyYAML path
# --------------------------------------------------------------------------- #

def check_with_yaml(path, doc, is_action):
    problems = []

    if is_action:
        runs = (doc or {}).get("runs") or {}
        if runs.get("using") != "composite":
            return problems
        for index, step in enumerate(runs.get("steps") or [], start=1):
            if not isinstance(step, dict):
                continue
            if "run" in step and "shell" not in step:
                label = step.get("name") or f"step {index}"
                problems.append(f"{label}: `run:` without `shell:`")
        return problems

    if not isinstance(doc, dict):
        return ["is not a YAML mapping"]
    if "permissions" not in doc:
        problems.append("no top-level `permissions:`")
    for job_id, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        if "timeout-minutes" not in job:
            problems.append(f"job `{job_id}`: no `timeout-minutes:`")
    return problems


# --------------------------------------------------------------------------- #
# stdlib fallback: an indentation scan of exactly the keys we assert on
# --------------------------------------------------------------------------- #

def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def check_text(text, is_action):
    lines = text.splitlines()
    problems = []

    if is_action:
        using_composite = any(
            re.match(r"^\s+using:\s*composite\s*(#.*)?$", line) for line in lines)
        if not using_composite:
            return problems

        in_steps = False
        steps_indent = 0
        step = None
        steps = []
        for line in lines:
            stripped = line.strip()
            if re.match(r"^\s*steps:\s*(#.*)?$", line):
                in_steps = True
                steps_indent = indent_of(line)
                continue
            if not in_steps or not stripped or stripped.startswith("#"):
                continue
            ind = indent_of(line)
            if ind <= steps_indent:
                in_steps = False
                continue
            if ind == steps_indent + 2 and stripped.startswith("- "):
                step = {"run": False, "shell": False, "name": None}
                body = stripped[2:]
                for key in ("run", "shell", "name"):
                    if re.match(rf"^{key}\s*:", body):
                        if key == "name":
                            step["name"] = body.split(":", 1)[1].strip()
                        else:
                            step[key] = True
                steps.append(step)
                continue
            if step is not None and ind == steps_indent + 4:
                match = re.match(r"^(run|shell)\s*:", stripped)
                if match:
                    step[match.group(1)] = True

        return [f"{item['name'] or 'step'}: `run:` without `shell:`"
                for item in steps if item["run"] and not item["shell"]]

    if not any(re.match(r"^permissions\s*:", line) for line in lines):
        problems.append("no top-level `permissions:`")

    in_jobs = False
    jobs_offset = 0
    job_starts = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^jobs\s*:\s*(#.*)?$", line):
            in_jobs = True
            jobs_offset = indent_of(line)
            continue
        if not in_jobs:
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if indent_of(line) <= jobs_offset:
            in_jobs = False
            continue
        match = re.match(r"^(\s{2})([A-Za-z0-9_-]+)\s*:\s*(#.*)?$", line)
        if match:
            job_starts.append((match.group(2), index))

    for position, (job_id, start) in enumerate(job_starts):
        end = job_starts[position + 1][1] if position + 1 < len(job_starts) else len(lines)
        span = lines[start:end]
        if not any(re.match(r"^\s+timeout-minutes\s*:", line) for line in span):
            problems.append(f"job `{job_id}`: no `timeout-minutes:`")
    return problems


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv):
    use_yaml = "--no-yaml" not in argv
    args = [a for a in argv if not a.startswith("--")]
    root = args[0] if args else "."

    workflows, actions = collect(root)
    if not workflows:
        print(f"workflow-lint: no workflows under {root}/.github/workflows", file=sys.stderr)
        return 1

    loader = None
    if use_yaml:
        try:
            import yaml  # noqa: PLC0415
            loader = yaml.safe_load
        except ImportError:
            print("workflow-lint: PyYAML not installed, using the stdlib scan")

    findings = []
    targets = [(path, False) for path in workflows] + [(path, True) for path in actions]
    for path, is_action in targets:
        text = open(path, encoding="utf-8").read()
        if loader is not None:
            try:
                doc = loader(text)
            except Exception as exc:  # noqa: BLE001 - report, do not traceback
                findings.append((path, [f"invalid YAML: {exc}"]))
                continue
            problems = check_with_yaml(path, doc, is_action)
        else:
            problems = check_text(text, is_action)
        if problems:
            findings.append((path, problems))

    for path, problems in findings:
        for problem in problems:
            print(f"{rel(root, path)}: {problem}", file=sys.stderr)
    checked = f"{len(workflows)} workflow(s), {len(actions)} composite action(s)"
    if findings:
        print(f"workflow-lint: FAIL ({checked})", file=sys.stderr)
        return 1
    print(f"workflow-lint: structural checks passed ({checked})")

    exe = shutil.which("actionlint")
    if exe is None:
        if os.environ.get("CI", "").lower() in ("1", "true", "yes"):
            print("ERROR: actionlint must be installed in CI", file=sys.stderr)
            return 1
        print("actionlint: skipped (not installed)")
        return 0

    version = subprocess.run([exe, "--version"], capture_output=True, text=True)
    print(f"actionlint: {version.stdout.splitlines()[0] if version.stdout else exe}")
    result = subprocess.run([exe, "-color", *sorted(workflows), *sorted(actions)], cwd=root)
    if result.returncode != 0:
        print("workflow-lint: FAIL (actionlint)", file=sys.stderr)
        return result.returncode
    print("workflow-lint: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
