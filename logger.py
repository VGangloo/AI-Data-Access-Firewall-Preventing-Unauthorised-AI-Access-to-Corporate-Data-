from datetime import datetime

def log_request(username,
                role,
                filename,
                decision):

    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    entry = (
        f"{timestamp} | "
        f"{username} | "
        f"{role} | "
        f"{filename} | "
        f"{decision}\n"
    )

    with open("logs.txt", "a") as f:
        f.write(entry)