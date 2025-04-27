# vuln_app.py

import sqlite3
import os
import subprocess

# --- Vulnérabilité 1: SQL Injection ---
def login(username, password):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

# --- Vulnérabilité 2: Hardcoded Credentials ---
SECRET_API_KEY = "12345-SECRET-KEY-HARDCODED"

# --- Vulnérabilité 3: Command Injection ---
def run_ping(ip_address):
    os.system(f"ping {ip_address}")

# --- Vulnérabilité 4: Path Traversal ---
def read_file(filename):
    with open("/var/data/" + filename, "r") as file:
        return file.read()

# --- Vulnérabilité 5: Insecure Deserialization ---
import pickle

def load_object(data):
    return pickle.loads(data)

# Exemples d'appel (danger: ne PAS exécuter ce fichier en production !)
if __name__ == "__main__":
    login("admin' OR '1'='1", "password")
    run_ping("; rm -rf /")
    read_file("../../etc/passwd")
