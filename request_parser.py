import re

# Allowed documents in the system
DOCUMENTS = {
    "announcement": ("announcement.txt", "Public"),
    "guidelines": ("guidelines.txt", "Internal"),
    "report": ("report.txt", "Confidential"),
    "salary": ("salary.txt", "Restricted")
}


def parse_request(message):

    message = message.lower().strip()

    # -----------------------------------
    # Block path traversal attempts
    # -----------------------------------

    blocked_patterns = [
        "../",
        "..\\",
        "/",
        "\\",
        ":"
    ]

    for pattern in blocked_patterns:

        if pattern in message:

            return ("INVALID_REQUEST", None)

    # -----------------------------------
    # Match known documents using
    # whole-word matching
    # -----------------------------------

    for keyword, (filename, sensitivity) in DOCUMENTS.items():

        if re.search(rf"\b{re.escape(keyword)}\b", message):

            return (filename, sensitivity)

    # -----------------------------------
    # Unknown document
    # -----------------------------------

    return (None, None)