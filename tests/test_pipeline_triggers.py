# tests/test_pipeline_triggers.py
#
# PURPOSE: Deliberately bad code to verify the security pipeline catches real issues.
# This file MUST be removed before any production release.
# Each section is labeled with which tool should catch it and why.
#
# TO USE:
#   1. Add this file to a branch
#   2. Open a PR — pipeline should flag findings in the Security tab
#   3. Confirm each tool fires
#   4. Delete this file, close the PR — never merge to main

import subprocess
import hashlib
import pickle
import os


# ─── GITLEAKS TRIGGERS ────────────────────────────────────────────────────────
# Gitleaks scans for secret patterns in source code.
# These look like real credentials and will match its ruleset.

AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN          = "ghp_R4nD0mFaK3T0k3nTh4tL00ksRe4l12345"
SECRET_KEY            = "super-secret-jwt-signing-key-do-not-commit"
DATABASE_URL          = "postgresql://admin:plaintext_password@prod-db.internal:5432/iam"


# ─── BANDIT TRIGGERS ──────────────────────────────────────────────────────────
# Bandit does static analysis on Python code patterns.

# B602 — shell injection risk: user input passed to shell=True
def run_command(user_input):
    subprocess.call(user_input, shell=True)


# B301 — pickle.loads() allows arbitrary code execution
def load_session(data):
    return pickle.loads(data)


# B324 — MD5 is cryptographically broken, never use for passwords
def hash_password_wrong(password):
    return hashlib.md5(password.encode()).hexdigest()


# B105 — hardcoded password string
def get_db_password():
    password = "hunter2"
    return password


# B603 + B607 — subprocess without shell=True still flagged if input not sanitized
def run_ls(path):
    subprocess.Popen(["ls", path])


# ─── SEMGREP TRIGGERS ─────────────────────────────────────────────────────────
# Semgrep uses pattern matching and taint analysis.

# SQL injection — string formatting directly into a query
def get_user(db, user_id):
    db.execute("SELECT * FROM users WHERE id = '%s'" % user_id)


# JWT decode with verification disabled — our custom rule catches this
def decode_token_wrong(token, secret):
    import jose.jwt
    return jose.jwt.decode(token, secret, options={"verify_signature": False})


# Broad exception swallow — our custom Semgrep rule catches this
def do_something_dangerous():
    try:
        risky_operation()
    except:
        pass


# ─── SCA / pip-audit TRIGGERS ─────────────────────────────────────────────────
# pip-audit checks your requirements.txt against CVE databases.
# You don't trigger this with code — you trigger it by pinning a known-vulnerable version.
#
# To test pip-audit specifically, temporarily add this to requirements.txt:
#
#   requests==2.18.0   # CVE-2018-18074 — known vulnerable, has patch
#
# Then revert after confirming pip-audit flags it.
# Don't add it here — this file is Python, not a requirements file.


def risky_operation():
    pass
