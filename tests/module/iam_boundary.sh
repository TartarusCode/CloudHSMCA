#!/bin/bash
# =============================================================================
# Every IAM role must honour permissions_boundary_arn.
#
# A plan cannot run offline (the module reads an AMI and the caller identity), so
# this checks the configuration directly: each `aws_iam_role` block must carry
# `permissions_boundary = var.permissions_boundary_arn`, and every module that
# declares a role must also declare the variable with a null default.
#
# A role added without the boundary is a hole that no other offline gate sees.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

python3 - "$REPO" <<'PY'
import os
import re
import sys

repo = sys.argv[1]
problems = []
roles = 0

for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d not in (".git", ".terraform", "node_modules")]
    for name in files:
        if not name.endswith(".tf"):
            continue
        path = os.path.join(root, name)
        text = open(path).read()
        for m in re.finditer(r'resource\s+"aws_iam_role"\s+"([^"]+)"\s*\{', text):
            roles += 1
            # take the block body by brace counting
            i = text.index("{", m.start())
            depth = 0
            for j in range(i, len(text)):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        body = text[i:j]
                        break
            else:
                problems.append("%s: aws_iam_role.%s has no closing brace" % (path, m.group(1)))
                continue
            if "permissions_boundary = var.permissions_boundary_arn" not in body:
                problems.append("%s: aws_iam_role.%s does not set permissions_boundary"
                                % (os.path.relpath(path, repo), m.group(1)))

if roles == 0:
    problems.append("no aws_iam_role resources found: the check found nothing to test")

# Every directory that declares a role must expose the variable with a null default.
for root, dirs, files in os.walk(repo):
    dirs[:] = [d for d in dirs if d not in (".git", ".terraform", "node_modules")]
    tf = [f for f in files if f.endswith(".tf")]
    if not tf:
        continue
    has_role = any('resource "aws_iam_role"' in open(os.path.join(root, f)).read() for f in tf)
    if not has_role:
        continue
    declared = False
    for f in tf:
        text = open(os.path.join(root, f)).read()
        if re.search(r'variable\s+"permissions_boundary_arn"\s*\{[^}]*default\s*=\s*null', text, re.S):
            declared = True
    if not declared:
        problems.append("%s: declares an aws_iam_role but not permissions_boundary_arn (default null)"
                        % os.path.relpath(root, repo))

if problems:
    print("IAM BOUNDARY: FAIL (%d role(s) checked)" % roles)
    for p in problems:
        print("  - " + p)
    sys.exit(1)

print("IAM BOUNDARY: PASS (%d role(s), every one bounded)" % roles)
PY
