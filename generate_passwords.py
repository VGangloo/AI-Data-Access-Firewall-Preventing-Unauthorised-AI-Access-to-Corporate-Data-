from werkzeug.security import generate_password_hash

print("employee123")
print(generate_password_hash("employee123"))

print()

print("manager123")
print(generate_password_hash("manager123"))

print()

print("admin123")
print(generate_password_hash("admin123"))