import json


def evaluate(role, sensitivity):

    with open("policies.json", "r") as f:
        policies = json.load(f)

    if sensitivity in policies.get(role, []):
        return "ALLOW"

    if role == "Employee" and sensitivity == "Confidential":
        return "REDACT"

    return "DENY"