def redact_content(text):

    sensitive_keywords = [
        "salary",
        "bank",
        "details"
    ]

    for word in sensitive_keywords:
        text = text.replace(word, "****")

    return text