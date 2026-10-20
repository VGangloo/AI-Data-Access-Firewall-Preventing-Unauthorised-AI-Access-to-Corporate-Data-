from flask import Flask, render_template, request, redirect, session
import json
import os
import time
from flask import abort
from datetime import datetime

from werkzeug.security import check_password_hash

from request_parser import parse_request
from policy_engine import evaluate
from redactor import redact_content
from logger import log_request


# --------------------------------------------------
# Flask App Configuration
# --------------------------------------------------

app = Flask(__name__)
app.secret_key = "firewall_secret_key"

# --------------------------------------------------
# Secure Session Configuration
# --------------------------------------------------

from datetime import timedelta

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Set to True when deploying with HTTPS
app.config["SESSION_COOKIE_SECURE"] = False

# Session expires after 30 minutes
app.permanent_session_lifetime = timedelta(minutes=30)

# --------------------------------------------------
# Dashboard Statistics
# --------------------------------------------------

def get_dashboard_stats():

    folders = [
        "documents/public",
        "documents/internal",
        "documents/confidential",
        "documents/restricted"
    ]

    document_count = 0

    for folder in folders:
        if os.path.exists(folder):
            document_count += len(os.listdir(folder))

    audit_events = 0
    violations = 0
    recent_logs = []

    if os.path.exists("logs.txt"):

        with open("logs.txt", "r") as f:
            logs = f.readlines()

        audit_events = len(logs)

        for log in logs:

            if "DENY" in log:
                violations += 1

        # Last 5 log entries (Newest First)

        for log in reversed(logs[-5:]):

            parts = log.strip().split(" | ")

            if len(parts) == 5:

                recent_logs.append({

                    "time": parts[0],
                    "user": parts[1],
                    "role": parts[2],
                    "file": parts[3],
                    "decision": parts[4]

                })

    with open("policies.json", "r") as f:
        policies = json.load(f)

    return {

        "firewall_status": "ACTIVE",
        "document_count": document_count,
        "audit_events": audit_events,
        "violations": violations,
        "policy_count": len(policies),
        "request_count": audit_events,
        "recent_logs": recent_logs

    }


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        with open("users.json", "r") as f:
            users = json.load(f)

        if username in users:
            stored_password = users[username]["password"]
            
            if check_password_hash(stored_password, password):
                session.permanent = True
                session["username"] = username
                session["role"] = users[username]["role"]
                session["login_time"] = datetime.now().strftime("%d %b %Y %H:%M")
                return redirect("/dashboard")

    return render_template("login.html")


# --------------------------------------------------
# Dashboard
# --------------------------------------------------

@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect("/")

    stats = get_dashboard_stats()

    return render_template(

        "dashboard.html",

        username=session["username"],
        role=session["role"],
        login_time=session.get("login_time", "Unknown"),
        stats=stats

    )


# --------------------------------------------------
# AI Security Assistant
# --------------------------------------------------

@app.route("/chatbot", methods=["GET", "POST"])
def chatbot():

    if "username" not in session:
        return redirect("/")

    if request.method == "POST":

        message = request.form["message"]

        start_time = time.perf_counter()

        filename, sensitivity = parse_request(message)

        # ----------------------------------
        # Invalid Request (Path Traversal etc.)
        # ----------------------------------

        if filename == "INVALID_REQUEST":

            log_request(
                session["username"],
                session["role"],
                "INVALID_REQUEST",
                "DENY"
            )

            latency = round((time.perf_counter() - start_time) * 1000, 2)

            return render_template(

                "chatbot.html",

                username=session["username"],
                role=session["role"],

                message=message,
                filename=None,
                decision="DENY",
                content="Invalid request detected. Possible malicious input was blocked.",
                latency=latency

            )

        # ----------------------------------
        # Unknown Document
        # ----------------------------------

        if filename is None:

            log_request(
                session["username"],
                session["role"],
                "UNKNOWN_DOCUMENT",
                "DENY"
            )

            latency = round((time.perf_counter() - start_time) * 1000, 2)

            return render_template(

                "chatbot.html",

                username=session["username"],
                role=session["role"],

                message=message,
                filename=None,
                decision="DENY",
                content="Requested document not recognised.",
                latency=latency

            )

        # ----------------------------------
        # Evaluate RBAC Policy
        # ----------------------------------

        decision = evaluate(
            session["role"],
            sensitivity
        )

        path = f"documents/{sensitivity.lower()}/{filename}"

        # ----------------------------------
        # Check if File Exists
        # ----------------------------------

        if not os.path.exists(path):

            log_request(
                session["username"],
                session["role"],
                filename,
                "FILE_NOT_FOUND"
            )

            latency = round((time.perf_counter() - start_time) * 1000, 2)

            return render_template(

                "chatbot.html",

                username=session["username"],
                role=session["role"],

                message=message,
                filename=filename,
                decision=decision,
                content="Requested document is unavailable.",
                latency=latency

            )

        # ----------------------------------
        # Read File
        # ----------------------------------

        if decision == "ALLOW":

            with open(path, "r") as f:
                content = f.read()

        elif decision == "REDACT":

            with open(path, "r") as f:
                content = redact_content(
                    f.read()
                )

        else:

            content = "Access Denied"

        # ----------------------------------
        # Audit Log
        # ----------------------------------

        log_request(

            session["username"],
            session["role"],
            filename,
            decision

        )

        # ----------------------------------
        # # Calculate Latency
        # # ----------------------------------
        
        latency = round((time.perf_counter() - start_time) * 1000, 2)

        # ----------------------------------
        # Display Result
        # ----------------------------------

        return render_template(

            "chatbot.html",

            username=session["username"],
            role=session["role"],

            message=message,
            filename=filename,
            decision=decision,
            content=content,
            latency=latency

        )
    
    

    # ----------------------------------
    # First Visit
    # ----------------------------------

    return render_template(

        "chatbot.html",

        username=session["username"],
        role=session["role"],

        message=None,
        filename=None,
        decision=None,
        content=None,
        latency=None


    )


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")

# --------------------------------------------------
# Protected Documents
# --------------------------------------------------

@app.route("/documents")
def documents():

    if "username" not in session:
        return redirect("/")

    documents = []

    folders = {
        "Public": "documents/public",
        "Internal": "documents/internal",
        "Confidential": "documents/confidential",
        "Restricted": "documents/restricted"
    }

    access_policy = {
        "Public": "All Users",
        "Internal": "Employee and Above",
        "Confidential": "Manager (Employee receives Redacted)",
        "Restricted": "Admin Only"
    }

    stats = {
        "total": 0,
        "public": 0,
        "internal": 0,
        "confidential": 0,
        "restricted": 0
    }

    for classification, folder in folders.items():

        if os.path.exists(folder):

            files = os.listdir(folder)

            for file in files:

                documents.append({

                    "name": file,
                    "classification": classification,
                    "policy": access_policy[classification],
                    "status": "Available"

                })

            stats["total"] += len(files)

            if classification == "Public":
                stats["public"] = len(files)

            elif classification == "Internal":
                stats["internal"] = len(files)

            elif classification == "Confidential":
                stats["confidential"] = len(files)

            elif classification == "Restricted":
                stats["restricted"] = len(files)

    return render_template(

        "documents.html",

        username=session["username"],
        role=session["role"],
        login_time=session.get("login_time", "Unknown"),

        documents=documents,
        stats=stats

    )


# --------------------------------------------------
# Audit Centre
# --------------------------------------------------

@app.route("/audit")
def audit():

    if "username" not in session:
        return redirect("/")

    if session.get("role") != "Admin":
        abort(403)

    logs = []

    total_logs = 0
    allow_count = 0
    redact_count = 0
    deny_count = 0

    if os.path.exists("logs.txt"):

        with open("logs.txt", "r") as f:

            lines = f.readlines()
            
            for line in reversed(lines):

                parts = line.strip().split(" | ")

                if len(parts) == 5:

                    log = {

                        "time": parts[0],
                        "user": parts[1],
                        "role": parts[2],
                        "file": parts[3],
                        "decision": parts[4]

                    }

                    logs.append(log)

                    total_logs += 1

                    if log["decision"] == "ALLOW":
                        allow_count += 1

                    elif log["decision"] == "REDACT":
                        redact_count += 1

                    elif log["decision"] == "DENY":
                        deny_count += 1



    return render_template(

        "audit.html",

        username=session["username"],
        role=session["role"],
        login_time=session.get("login_time", "Unknown"),

        logs=logs,

        total_logs=total_logs,
        allow_count=allow_count,
        redact_count=redact_count,
        deny_count=deny_count

    )


# --------------------------------------------------
# Run Application
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)


