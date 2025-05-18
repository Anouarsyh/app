import streamlit as st
import pandas as pd
import requests
import json
import os
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration de la page Streamlit
st.set_page_config(page_title="EDR Automation Assistant", layout="wide")

# Charger la configuration
def load_config():
    with open("config.json", "r") as config_file:
        config = json.load(config_file)
    return config

# Fonction pour interroger l'API EDR - Machines en ligne
def get_online_machines(file_path):
    print("Starting analysis of online machines...")
    config = load_config()
    username = config["username"]
    password = config["password"]
    server = config["server"]
    port = config["port"]
    base_url = f"https://{server}:{port}"
    login_url = base_url + "/login.html"
    api_url = base_url + "/rest/sensors/query"

    # Lire le fichier Excel
    dataframe = pd.read_excel(file_path)
    machine_names = dataframe.iloc[:, 3].dropna().tolist()  # Colonne des machines
    print("Machines retrieved from Excel file:", machine_names)

    session = requests.session()
    print("Attempting to connect to EDR...")
    login_response = session.post(login_url, data={"username": username, "password": password}, verify=True)
    if login_response.status_code != 200:
        print("Connection error, code:", login_response.status_code)
        return []  # Connection failure
    print("Connection successful!")

    machines_with_online_sensors = []
    headers = {"Content-Type": "application/json"}
    for machine_name in machine_names:
        filters = [
            {"fieldName": "machineName", "operator": "Equals", "values": [machine_name]},
            {"fieldName": "status", "operator": "Equals", "values": ["Online"]}
        ]
        query = json.dumps({"limit": 20000, "offset": 0, "sortDirection": "ASC", "filters": filters})
        print(f"Sending request for {machine_name}...")
        api_response = session.post(api_url, data=query, headers=headers)
        if api_response.status_code == 200:
            response_data = api_response.json()
            num_sensors = len(response_data.get("sensors", []))
            print(f"{num_sensors} sensor(s) found for {machine_name}")
            if num_sensors > 0:
                machines_with_online_sensors.append(machine_name)
        else:
            print(f"API error for {machine_name}, code:", api_response.status_code)

    print("Machines with online sensors:", machines_with_online_sensors)
    return machines_with_online_sensors, session, machine_names


# Fonction modifiée pour récupérer les Malops avec filtres
def get_malops(config, severity_filter=None, status_filter=None):
    print("Starting Malops retrieval with filters...")
    # Login information
    username = config["username"]
    password = config["password"]
    server = config["server"]
    port = config["port"]

    data = {
        "username": username,
        "password": password
    }

    headers = {"Content-Type": "application/json"}

    base_url = "https://" + server + ":" + port
    login_url = base_url + "/login.html"

    print(f"Attempting to connect to {base_url}...")
    session = requests.session()
    response = session.post(login_url, data=data, verify=True)
    
    if response.status_code != 200:
        print(f"Connection failed: {response.status_code}")
        return None, session

    print("Connection successful, retrieving Malops...")
    # Request URL
    endpoint_url = "/rest/mmng/v2/malops"
    api_url = base_url + endpoint_url

    time_range_start = 0
    time_range_end = 164633936634499999
    
    # Build the filter based on parameters
    filter_query = {"malop": {}}
    
    # Apply status filter
    if status_filter and status_filter != "All":
        filter_query["malop"]["status"] = [status_filter]
    
    # Apply severity filter
    if severity_filter and len(severity_filter) > 0:
        filter_query["malop"]["severity"] = severity_filter

    query = json.dumps({
        "search": {},
        "range": {"from": time_range_start, "to": time_range_end},
        "pagination": {"pageSize": 100, "offset": 0},
        "filter": filter_query
    })

    print(f"Sending request to {api_url} with filters: {filter_query}")
    api_response = session.request("POST", api_url, data=query, headers=headers)
    
    if api_response.status_code == 200:
        print(f"Response received: {len(api_response.content)} bytes")
        return json.loads(api_response.content), session
    else:
        print(f"Error retrieving Malops: {api_response.status_code}")
        return None, session
# Fonction pour analyser les malops
def analyze_malops(malops_data):
    """Analyze malops to extract important information"""
    print("Starting detailed Malops analysis...")
    
    if not malops_data or "data" not in malops_data or not malops_data["data"].get("data"):
        print("No Malop data found for analysis")
        return {}
    
    malops = malops_data["data"]["data"]
    
    # Analyse par type de détection
    detection_types = {}
    for malop in malops:
        dtype = malop.get("detectionType", "Unknown")
        detection_types[dtype] = detection_types.get(dtype, 0) + 1
    
    # Analyse par machine
    machines = {}
    for malop in malops:
        for machine in malop.get("machines", []):
            machine_name = machine.get("displayName", "Unknown")
            if machine_name not in machines:
                machines[machine_name] = {
                    "count": 0,
                    "os_type": machine.get("osType", "Unknown"),
                    "connected": machine.get("connected", False),
                    "isolated": machine.get("isolated", False)
                }
            machines[machine_name]["count"] += 1
    
    # Analyse temporelle (création des Malops)
    now = datetime.now()
    time_periods = {
        "last_24h": 0,
        "last_week": 0,
        "last_month": 0,
        "older": 0
    }
    
    for malop in malops:
        creation_time = malop.get("creationTime", 0)
        if creation_time:
            creation_date = datetime.fromtimestamp(creation_time / 1000)  # Convert to seconds
            delta = now - creation_date
            
            if delta < timedelta(days=1):
                time_periods["last_24h"] += 1
            elif delta < timedelta(days=7):
                time_periods["last_week"] += 1
            elif delta < timedelta(days=30):
                time_periods["last_month"] += 1
            else:
                time_periods["older"] += 1
    
    # Récupérer les tactiques et techniques MITRE ATT&CK
    mitre_tactics = {}
    mitre_techniques = {}
    
    for malop in malops:
        for tactic in malop.get("mitreTactics", []):
            mitre_tactics[tactic] = mitre_tactics.get(tactic, 0) + 1
        
        for technique in malop.get("mitreTechniques", []):
            mitre_techniques[technique] = mitre_techniques.get(technique, 0) + 1
    
    # Analyse des sévérités directement depuis les données
    severities = {}
    priorities = {}
    statuses = {}
    
    for malop in malops:
        # Severity
        severity = malop.get("severity", "Unknown")
        severities[severity] = severities.get(severity, 0) + 1
        
        # Priority
        priority = malop.get("priority", "Unknown")
        priorities[priority] = priorities.get(priority, 0) + 1
        
        # Status
        status = malop.get("status", "Unknown")
        statuses[status] = statuses.get(status, 0) + 1
    
    print(f"Analysis completed: {len(detection_types)} detection types, {len(machines)} machines")
    
    return {
        "detection_types": detection_types,
        "affected_machines": machines,
        "time_periods": time_periods,
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "severities": severities,
        "priorities": priorities,
        "statuses": statuses
    }

def display_malops_dashboard(malops_data, analysis_data):
    """Display a complete Malops dashboard"""
    if not malops_data or "data" not in malops_data or not malops_data["data"].get("data"):
        st.warning("No Malop data to display")
        return
    
    malops = malops_data["data"]["data"]
    
    # Afficher les statistiques globales
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Malops", len(malops))
    
    with col2:
        # Obtenir le nombre de malops par sévérité
        severities = analysis_data.get("severities", {})
        high_count = severities.get("High", 0)
        st.metric("High Malops", high_count)
    
    with col3:
        # Obtenir le nombre de malops par priorité
        priorities = analysis_data.get("priorities", {})
        high_priority = priorities.get("HIGH", 0)
        st.metric("High Priority", high_priority)
    
    with col4:
        # Obtenir le nombre de malops par statut
        statuses = analysis_data.get("statuses", {})
        active_count = statuses.get("Active", 0)
        st.metric("Active Malops", active_count)
    
    # Graphique des sévérités
    st.subheader("Severity Distribution")
    
    # Préparer les données pour le graphique
    severities = analysis_data.get("severities", {})
    sev_data = {
        "Severity": list(severities.keys()),
        "Count": list(severities.values())
    }
    sev_df = pd.DataFrame(sev_data)
    
    # Définir des couleurs appropriées pour chaque niveau de sévérité
    severity_colors = {
        "High": "red",
        "Medium": "yellow",
        "Low": "green"
    }
    
    colors = [severity_colors.get(sev, "gray") for sev in sev_df["Severity"]]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(sev_df["Severity"], sev_df["Count"], color=colors)
    ax.set_title("Malops Distribution by Severity Level")
    ax.set_ylabel("Number of Malops")
    st.pyplot(fig)
    
    # Graphique des types de détection
    if analysis_data.get("detection_types"):
        st.subheader("Detection Types")
        det_df = pd.DataFrame({
            "Type": list(analysis_data["detection_types"].keys()),
            "Count": list(analysis_data["detection_types"].values())
        })
        
        fig2, ax2 = plt.subplots(figsize=(10, 6))
        ax2.pie(det_df["Count"], labels=det_df["Type"], autopct='%1.1f%%')
        ax2.set_title("Detection Types Distribution")
        st.pyplot(fig2)
    
    # Tableau détaillé des Malops avec statut de validation
    st.subheader("Malops List")
    
    # Convertir les données en DataFrame
    malops_table = []
    for malop in malops:
        malop_id = malop.get("guid", "N/A")
        machines_list = ", ".join([m.get("displayName", "Unknown") for m in malop.get("machines", [])])
        validation_status = get_validation_status(malop_id)
        
        malops_table.append({
            "ID": malop_id,
            "Name": malop.get("displayName", "Unknown"),
            "Detection Type": malop.get("detectionType", "Unknown"),
            "Severity": malop.get("severity", "Unknown"),
            "Priority": malop.get("priority", "Unknown"),
            "Status": malop.get("status", "Unknown"),
            "Creation Date": datetime.fromtimestamp(malop.get("creationTime", 0)/1000).strftime("%Y-%m-%d %H:%M"),
            "Affected Machines": machines_list,
            "Validation Status": validation_status  # Nouvelle colonne
        })
    
    malops_df = pd.DataFrame(malops_table)
    st.dataframe(malops_df, use_container_width=True)
    
    # Ajout du formulaire de validation (après le tableau)
    st.subheader("Validate Malop")
    
    col1, col2 = st.columns(2)
    
    with col1:
        selected_malop_id = st.selectbox(
            "Select Malop to validate",
            options=[m.get("guid", "N/A") for m in malops],
            format_func=lambda x: next((m.get("displayName", "Unknown") for m in malops if m.get("guid") == x), x)
        )
    
    with col2:
        current_status = get_validation_status(selected_malop_id)
        new_status = st.radio(
            "Validation status",
            options=["Suspect", "Confirmed", "False Positive"],
            index=["Suspect", "Confirmed", "False Positive"].index(current_status)
        )
    
    # Bouton de validation
    if st.button("Update Validation Status"):
        update_validation_status(selected_malop_id, new_status)
        st.success(f"Validation status updated to '{new_status}' for Malop {selected_malop_id}")
        st.rerun()  # Recharger la page pour afficher le statut mis à jour
    
    # Actions disponibles
    st.subheader("Available Actions")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Export Data (CSV)"):
            # Create the report directory if it doesn't exist
            os.makedirs("reports", exist_ok=True)
            
            # Export to CSV
            export_path = "reports/malops_export.csv"
            malops_df.to_csv(export_path, index=False)
            st.success(f"Data successfully exported to {export_path}")
    
    with col2:
        if st.button("Generate Detailed Report"):
            st.info("Generating report...")
            # Here we could add functionality to generate a more detailed report
            st.warning("Feature under development")
# Function to isolate a machine
def isolate_machine(session, machine_id, malop_id):
    """Isolate a machine connected to a Malop"""
    print(f"Attempting to isolate machine: {machine_id}")
    
    config = load_config()
    server = config["server"]
    port = config["port"]
    
    base_url = f"https://{server}:{port}"
    endpoint_url = "/rest/monitor/global/commands/isolate"
    api_url = base_url + endpoint_url
    
    headers = {"Content-Type": "application/json"}
    query = json.dumps({"pylumIds": [machine_id], "malopId": malop_id})
    
    api_response = session.request("POST", api_url, data=query, headers=headers)
    
    if api_response.status_code == 200:
        response_data = json.loads(api_response.content)
        print(f"Isolation response: {response_data}")
        return True, response_data
    else:
        print(f"Isolation failed, status code: {api_response.status_code}")
        return False, None

# Function to un-isolate a machine
def unisolate_machine(session, machine_id, malop_id):
    """Un-isolate a previously isolated machine"""
    print(f"Attempting to un-isolate machine: {machine_id}")
    
    config = load_config()
    server = config["server"]
    port = config["port"]
    
    base_url = f"https://{server}:{port}"
    endpoint_url = "/rest/monitor/global/commands/un-isolate"
    api_url = base_url + endpoint_url
    
    headers = {"Content-Type": "application/json"}
    query = json.dumps({"pylumIds": [machine_id], "malopId": malop_id})
    
    api_response = session.request("POST", api_url, data=query, headers=headers)
    
    if api_response.status_code == 200:
        response_data = json.loads(api_response.content)
        print(f"Un-isolation response: {response_data}")
        return True, response_data
    else:
        print(f"Un-isolation failed, status code: {api_response.status_code}")
        return False, None

# Function for custom remediation actions (quarantine file, kill process, etc.)
def perform_remediation_action(session, action_type, target_name, target_id, machine_name, machine_id):
    """Perform a specific remediation action
    
    Parameters:
    action_type (str): Type of action. Options: QUARANTINE_FILE, KILL_PROCESS, DELETE_REGISTRY_KEY, BLOCK_FILE
    """
    print(f"Performing remediation action: {action_type} for {target_name} on {machine_name}")
    
    config = load_config()
    server = config["server"]
    port = config["port"]
    
    base_url = f"https://{server}:{port}"
    endpoint_url = "/rest/detection/remediate-custom-actions"
    api_url = base_url + endpoint_url
    
    headers = {"Content-Type": "application/json"}
    
    # Create unique ID for the remediation
    remediation_id = f"{action_type}::{target_id}"
    
    # Prepare the query payload
    payload = [{
        "remediationType": action_type,
        "targetName": target_name,
        "targetId": target_id,
        "machineName": machine_name,
        "machineId": machine_id,
        "machinesCount": 1,
        "uniqueId": remediation_id
    }]
    
    query = json.dumps(payload)
    
    api_response = session.request("POST", api_url, data=query, headers=headers)
    
    if api_response.status_code == 200:
        response_data = json.loads(api_response.content)
        print(f"Remediation response: {response_data}")
        return True, response_data
    else:
        print(f"Remediation failed, status code: {api_response.status_code}")
        return False, None
   
    
#################################
# 1. Ajouter cette fonction pour définir les règles

def define_decision_rules():
    """Définit les règles de décision basées sur NIST"""
    rules = [
        {
            "id": "rule_1_credential_theft",
            "name": "Credential Theft Detection",
            "conditions": lambda m: m.get("detectionType") == "CREDENTIAL_THEFT",
            "actions": ["isolate", "notify"],
            "description": "Isole la machine et alerte lors de détection de vol de credentials. Référence: NIST Step 4."
        },
        {
            "id": "rule_2_ransomware",
            "name": "Ransomware Detection",
            "conditions": lambda m: m.get("detectionType") == "RANSOMWARE",
            "actions": ["isolate", "kill_process", "quarantine_file", "notify"],
            "description": "Isole immédiatement la machine, tue les processus malveillants et met en quarantaine les fichiers lors d'une détection de ransomware. Référence: NIST 800-61r2 Step 4."
        },
        {
            "id": "rule_3_auto_unisolate",
            "name": "Auto-Unisolate Remediated",
            "conditions": lambda m: m.get("status") == "Remediated",
            "machine_conditions": lambda machine: machine.get("isolated", False),
            "actions": ["unisolate"],
            "description": "Lève l'isolation automatiquement pour les machines remédiées. Référence: NIST Step 5."
        }
    ]
    return rules


# 3. Ajouter cette fonction pour envoyer des alertes (à implémenter selon vos besoins)

# Ajouter la fonction pour envoyer des emails
def send_email_notification(message):
    """Envoie une notification par email pour les réponses automatiques"""
    try:
        # Configuration de l'email
        sender_email = "anwarsayh98@gmail.com"  # À modifier
        receiver_email = "anouar.sayah03@gmail.com"  # Le destinataire souhaité
        password = ""  # À modifier
        
        # Créer le message
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = "Alerte EDR - Réponse automatisée"
        
        # Ajouter du contenu
        msg.attach(MIMEText(message, 'plain'))
        
        # Connexion au serveur et envoi
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg)
        server.quit()
        
        print(f"Email envoyé avec succès à {receiver_email}")
        return True
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email: {str(e)}")
        return False

# Modifier la fonction d'alerte pour utiliser l'email
def send_alert(message):
    """Envoie une alerte par email"""
    st.warning(message)
    # Envoyer l'email
    success = send_email_notification(message)
    # Log le message dans tous les cas
    print(f"ALERT: {message}")
    return success
##############################

# Fonction améliorée pour exécuter les actions d'une règle
def execute_rule_automatically(rule, malop, machine, session):
    """Exécute une règle en mode automatique apres confirmation Analyste"""
    rule_record = {
        "rule_id": rule.get("id", "unknown"),
        "rule_name": rule["name"],
        "malop_id": malop.get("guid", "N/A"),
        "malop_name": malop.get("displayName", "Unknown"),
        "machine": machine.get("displayName", "Unknown"),
        "actions": ", ".join(rule["actions"]),
        "executed_at": datetime.now().strftime('%d/%m/%Y at %H:%M:%S'),
        "status": "Initiated"
    }
    
    action_results = []
    
    # Exécuter les actions recommandées
    for action in rule["actions"]:
        if action == "isolate":
            success, response = isolate_machine(session, machine.get('guid', ''), malop.get('guid', ''))
            action_results.append({"action": "isolate", "success": success})
            
        elif action == "unisolate":
            success, response = unisolate_machine(session, machine.get('guid', ''), malop.get('guid', ''))
            action_results.append({"action": "unisolate", "success": success})
            
        elif action == "kill_process":
            success, response = perform_remediation_action(
                session,
                "KILL_PROCESS",
                "malicious_process",
                f"auto-kill-{int(time.time())}",
                machine.get('displayName', 'Unknown'),
                machine.get('guid', '')
            )
            action_results.append({"action": "kill_process", "success": success})
            
        elif action == "quarantine_file":
            success, response = perform_remediation_action(
                session,
                "QUARANTINE_FILE",
                "suspicious_file",
                f"auto-quarantine-{int(time.time())}",
                machine.get('displayName', 'Unknown'),
                machine.get('guid', '')
            )
            action_results.append({"action": "quarantine_file", "success": success})
            
        elif action == "delete_registry_key":
            success, response = perform_remediation_action(
                session,
                "DELETE_REGISTRY_KEY",
                "malicious_registry_key",
                f"auto-delete-reg-{int(time.time())}",
                machine.get('displayName', 'Unknown'),
                machine.get('guid', '')
            )
            action_results.append({"action": "delete_registry_key", "success": success})
            
        elif action == "block_file":
            success, response = perform_remediation_action(
                session,
                "BLOCK_FILE",
                "malicious_file",
                f"auto-block-{int(time.time())}",
                machine.get('displayName', 'Unknown'),
                machine.get('guid', '')
            )
            action_results.append({"action": "block_file", "success": success})
            
        elif action == "notify":
            success = send_alert(f"🔔 Alerte automatique: {rule['name']} déclenché pour {machine.get('displayName', 'Unknown')} - {malop.get('displayName', 'Unknown')}")
            action_results.append({"action": "notify", "success": success})
            
        elif action == "monitor":
            # Simuler une action de surveillance
            success = True  # Toujours réussie pour l'instant
            action_results.append({"action": "monitor", "success": success})
    
    # Mettre à jour le statut dans l'enregistrement
    all_successful = all(result["success"] for result in action_results)
    rule_record["status"] = "Completed" if all_successful else "Partially Failed"
    rule_record["results"] = ", ".join([f"{r['action']}: {'✅' if r['success'] else '❌'}" for r in action_results])
    
    # Ajouter à l'historique
    if not hasattr(st.session_state, 'rules_history'):
        st.session_state.rules_history = []
    
    st.session_state.rules_history.append(rule_record)
    
    return all_successful, rule_record

# Fonction modifiée pour analyser et appliquer les règles automatiquement
def analyze_rules_automatically(malops_data, session, automatic_rules=None):
    """Analyse les malops et applique les règles automatiquement"""
    if not automatic_rules:
        automatic_rules = define_decision_rules()
    
    results = []
    
    if not malops_data or "data" not in malops_data or not malops_data["data"].get("data"):
        return results
    
    malops = malops_data["data"]["data"]
    
    for malop in malops:
        malop_id = malop.get("guid", "N/A")
        validation_status = get_validation_status(malop_id)
        
        # Vérifier si le Malop est confirmé avant d'appliquer des règles automatiques
        if validation_status != "Confirmed":
            print(f"Malop {malop_id} non confirmé (statut: {validation_status}). Actions automatiques désactivées.")
            continue
        
        # Vérifier si le malop correspond à des règles
        for rule in automatic_rules:
            # Vérifier si la règle est active dans la session
            rule_id = rule.get("id", "unknown")
            rule_key = f"{rule_id}_active"
            
            # Si la clé n'existe pas, on considère la règle comme active par défaut
            rule_is_active = st.session_state.get(rule_key, True)
            
            if rule_is_active and rule["conditions"](malop):
                # Pour chaque machine affectée
                for machine in malop.get("machines", []):
                    # Vérifier les conditions de la machine si elles existent
                    machine_condition_met = True
                    if "machine_conditions" in rule:
                        machine_condition_met = rule["machine_conditions"](machine)
                    
                    if machine_condition_met:
                        # Exécuter les actions définies par la règle
                        success, record = execute_rule_automatically(rule, malop, machine, session)
                        results.append(record)
                        
                        # Envoyer une notification détaillée par email
                        email_message = f"""
                        Alerte EDR - Réponse automatisée
                        
                        Une règle de réponse automatisée a été déclenchée:
                        - Règle: {rule['name']} (ID: {rule_id})
                        - Description: {rule['description']}
                        - Actions: {', '.join(rule['actions'])}
                        - Machine: {machine.get('displayName', 'Unknown')}
                        - Malop: {malop.get('displayName', 'Unknown')}
                        - Date/heure: {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}
                        - Résultat: {'Succès' if success else 'Échec partiel'}
                        
                        Connectez-vous à l'application EDR Automation Assistant pour plus de détails.
                        """
                        send_alert(email_message)
    
    return results

# 1. Ajoutons d'abord une fonction pour gérer la validation des Malops

def initialize_validation_status():
    """Initialise le statut de validation des Malops s'il n'existe pas déjà"""
    if 'validation_statuses' not in st.session_state:
        st.session_state.validation_statuses = {}

def update_validation_status(malop_id, status):
    """Met à jour le statut de validation d'un Malop"""
    initialize_validation_status()
    st.session_state.validation_statuses[malop_id] = status
    
    # Enregistrer dans un fichier pour persistance entre les sessions (optionnel)
    try:
        os.makedirs("data", exist_ok=True)
        with open("data/validation_statuses.json", "w") as f:
            json.dump(st.session_state.validation_statuses, f)
    except Exception as e:
        print(f"Erreur lors de l'enregistrement des statuts de validation: {e}")

def get_validation_status(malop_id):
    """Récupère le statut de validation d'un Malop"""
    initialize_validation_status()
    
    # Essayer de charger depuis le fichier si c'est la première fois
    if not st.session_state.validation_statuses and os.path.exists("data/validation_statuses.json"):
        try:
            with open("data/validation_statuses.json", "r") as f:
                st.session_state.validation_statuses = json.load(f)
        except Exception as e:
            print(f"Erreur lors du chargement des statuts de validation: {e}")
    
    # Retourner le statut ou "Suspect" par défaut
    return st.session_state.validation_statuses.get(malop_id, "Suspect")



# Interface Streamlit principale
st.image("logo/2.png", width=100)
st.title("EDR Automation Assistant")

# Navigation par onglets - 4 onglets (après fusion)
tab1, tab2, tab3, tab4 = st.tabs([
    "Machine Analysis",  
    "Retrieve Malops", 
    "Remediation & Response",
    "Auto Response"
])

# Onglet 1: Analyse des machines  
with tab1:
    st.header("Machine Analysis")
    
    st.write("Upload an Excel file containing machine names")
    uploaded_file = st.file_uploader("Upload Excel file", type=["xlsx"])
    
    if uploaded_file:
        file_path = "tracker/test.xlsx"
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success("File uploaded successfully!")
        print("Excel file saved to:", file_path)
        
        # Exécuter l'analyse
        if st.button("Analyze Machines"):
            st.write("Analysis in progress...")
            machines_online, session, all_machines = get_online_machines(file_path)
            
            if machines_online:
                # Stocker les résultats en session_state pour les autres onglets
                st.session_state.machines_online = machines_online
                st.session_state.session = session
                st.session_state.all_machines = all_machines
                st.session_state.config = load_config()
                
                # Affichage amélioré
                col1, col2 = st.columns(2)
                
                with col1:
                    st.success(f"{len(machines_online)} online machines found!")
                    st.dataframe(pd.DataFrame(machines_online, columns=["Online Machines"]))
                
                with col2:
                    # Machines hors ligne
                    offline_machines = [m for m in all_machines if m not in machines_online]
                    st.warning(f"{len(offline_machines)} offline machines")
                    st.dataframe(pd.DataFrame(offline_machines, columns=["Offline Machines"]))
                
                # Graphique
                fig, ax = plt.subplots()
                ax.pie([len(machines_online), len(offline_machines)], 
                       labels=['Online', 'Offline'], 
                       autopct='%1.1f%%', 
                       colors=['green', 'red'])
                st.pyplot(fig)
                
                # Actions supplémentaires
                st.subheader("Additional Actions")
                action_col1, action_col2 = st.columns(2)
                
                with action_col1:
                    if st.button("Export Results to CSV"):
                        # Préparer les données pour l'export
                        export_data = pd.DataFrame({
                            "Machine": all_machines,
                            "Status": ["Online" if m in machines_online else "Offline" for m in all_machines]
                        })
                        
                        # Enregistrer en CSV
                        export_path = "reports/machine_status.csv"
                        os.makedirs(os.path.dirname(export_path), exist_ok=True)
                        export_data.to_csv(export_path, index=False)
                        
                        st.success(f"Results successfully exported to {export_path}")
                
                    

# Onglet 3: Retrieve Malops - Implémentation modifiée
with tab2:
    st.header("Malops Dashboard")
    
    # Options de filtrage
    st.subheader("Filter Options")
    col1, col2 = st.columns(2)
    
    with col1:
        severity_filter = st.multiselect(
            "Filter by severity",
            ["High", "Medium", "Low"],
            default=["Low", "Medium", "High"]
        )
    
    with col2:
        status_filter = st.radio(
            "Status",
            ["Active", "Remediated", "Closed", "Excluded", "All"],
            index=0
        )
    
    
    # Bouton pour récupérer les Malops
    if st.button("Retrieve and analyze Malops"):
        with st.spinner("Retrieving and analyzing Malops..."):
            try:
                # Récupérer les données des Malops avec les filtres sélectionnés
                config = load_config()
                malops_data, session = get_malops(
                    config, 
                    severity_filter=severity_filter, 
                    status_filter=status_filter
                )
                
                if malops_data:
                    # Analyser les données
                    analysis_results = analyze_malops(malops_data)
                    
                    # Stocker les résultats dans l'état de session
                    st.session_state.malops_data = malops_data
                    st.session_state.malops_analysis = analysis_results
                    st.session_state.session = session
                    
                    # Afficher le tableau de bord
                    display_malops_dashboard(malops_data, analysis_results)
                    
                    # Bouton pour voir les données brutes (développeurs)
                    with st.expander("View raw data (Developers)"):
                        st.json(malops_data)
                else:
                    st.error("Error retrieving Malops. Check connection and configuration settings.")
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
                print(f"Detailed exception: {e}")
    
    # Si des données existent déjà dans l'état de session, afficher le tableau de bord
    elif hasattr(st.session_state, 'malops_data') and st.session_state.malops_data:
        display_malops_dashboard(
            st.session_state.malops_data,
            st.session_state.malops_analysis
        )



# Tab 3: Remediation & Response
# Tab 3: Remediation & Response
with tab3:
    st.header("Remediation & Response")
    
    # Ajout des imports nécessaires
    from fpdf import FPDF
    import base64
    import io
    
    if hasattr(st.session_state, 'malops_data') and st.session_state.malops_data:
        # SECTION 1: Malop Selection and Information
        st.subheader("1. Malop Selection and Information")
        
        # Display available Malops for remediation
        malops = st.session_state.malops_data["data"]["data"]
        malops_options = {f"{m.get('displayName', 'Unknown')} ({m.get('guid', 'N/A')})": m.get('guid', 'N/A') for m in malops}
        
        selected_malop = st.selectbox(
            "Select a Malop for remediation",
            list(malops_options.keys())
        )
        
        if selected_malop:
            malop_id = malops_options[selected_malop]
            
            # Retrieve details of the selected Malop
            selected_malop_data = next((m for m in malops if m.get('guid') == malop_id), None)
            
            if selected_malop_data:
                # Display Malop information
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write(f"**Detection type:** {selected_malop_data.get('detectionType', 'Unknown')}")
                    st.write(f"**Severity:** {selected_malop_data.get('severity', 'Unknown')}")
                
                with col2:
                    st.write(f"**Priority:** {selected_malop_data.get('priority', 'Unknown')}")
                    st.write(f"**Status:** {selected_malop_data.get('status', 'Unknown')}")
                
                with col3:
                    creation_time = selected_malop_data.get('creationTime', 0)
                    if creation_time:
                        st.write(f"**Creation date:** {datetime.fromtimestamp(creation_time/1000).strftime('%Y-%m-%d %H:%M')}")
                
                # List affected machines
                machines = selected_malop_data.get('machines', [])
                if machines:
                    st.subheader("Affected machines:")
                    
                    # Create a multiselect for machines
                    machine_options = {m.get('displayName', 'Unknown'): m for m in machines}
                    selected_machine_names = st.multiselect(
                        "Select machines for remediation", 
                        list(machine_options.keys()),
                        default=list(machine_options.keys())[:1] if machine_options else None
                    )
                    
                    # Store selected machines in session state
                    if selected_machine_names:
                        st.session_state.selected_machines = [machine_options[name] for name in selected_machine_names]
                    else:
                        st.session_state.selected_machines = []
                    
                    # Display machines in a dataframe with selection status
                    machine_data = []
                    for machine in machines:
                        machine_name = machine.get('displayName', 'Unknown')
                        is_selected = machine_name in selected_machine_names
                        machine_data.append({
                            "Name": machine_name,
                            "Status": "🟢 Online" if machine.get('connected') else "🔴 Offline",
                            "Isolation": "🔒 Isolated" if machine.get('isolated') else "🔓 Not isolated",
                            "OS": machine.get('osType', 'Unknown'),
                            "Selected": "✅" if is_selected else ""
                        })
                    
                    st.dataframe(pd.DataFrame(machine_data))
                
                # Display MITRE ATT&CK information if available
                col1, col2 = st.columns(2)
                
                with col1:
                    mitre_tactics = selected_malop_data.get('mitreTactics', [])
                    if mitre_tactics:
                        st.subheader("MITRE ATT&CK Tactics:")
                        for tactic in mitre_tactics:
                            st.write(f"- {tactic}")
                
                with col2:
                    mitre_techniques = selected_malop_data.get('mitreTechniques', [])
                    if mitre_techniques:
                        st.subheader("MITRE ATT&CK Techniques:")
                        for technique in mitre_techniques:
                            st.write(f"- {technique}")

        # Remediation Actions section
        st.subheader("Remediation Actions")
        
        # Check if we have selected machines
        if hasattr(st.session_state, 'selected_machines') and st.session_state.selected_machines:
            selected_machines = st.session_state.selected_machines
            
            # Show isolation controls for all selected machines
            st.write(f"**Number of selected machines:** {len(selected_machines)}")
            
            # Batch isolation controls
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("Isolate All Selected Machines"):
                    isolation_results = []
                    with st.spinner("Isolating machines..."):
                        for machine in selected_machines:
                            machine_id = machine.get('guid', '')
                            machine_name = machine.get('displayName', 'Unknown')
                            
                            if not machine.get('isolated', False):
                                success, response = isolate_machine(
                                    st.session_state.session, 
                                    machine_id, 
                                    malop_id
                                )
                                
                                isolation_results.append({
                                    "machine": machine_name,
                                    "success": success,
                                    "was_already_isolated": False
                                })
                                
                                if success:
                                    # Update the machine's isolation status
                                    machine['isolated'] = True
                            else:
                                isolation_results.append({
                                    "machine": machine_name,
                                    "success": True,
                                    "was_already_isolated": True
                                })
                        
                        # Show results
                        st.write("Isolation results:")
                        for result in isolation_results:
                            if result["was_already_isolated"]:
                                st.info(f"Machine {result['machine']} was already isolated.")
                            elif result["success"]:
                                st.success(f"Machine {result['machine']} isolated successfully!")
                            else:
                                st.error(f"Failed to isolate machine: {result['machine']}")
                        
                        if all(result["success"] for result in isolation_results):
                            st.success("All selected machines have been isolated successfully!")
                            st.rerun()
            
            with col2:
                if st.button("Un-isolate All Selected Machines"):
                    unisolation_results = []
                    with st.spinner("Un-isolating machines..."):
                        for machine in selected_machines:
                            machine_id = machine.get('guid', '')
                            machine_name = machine.get('displayName', 'Unknown')
                            
                            if machine.get('isolated', False):
                                success, response = unisolate_machine(
                                    st.session_state.session, 
                                    machine_id, 
                                    malop_id
                                )
                                
                                unisolation_results.append({
                                    "machine": machine_name,
                                    "success": success,
                                    "was_already_unisolated": False
                                })
                                
                                if success:
                                    # Update the machine's isolation status
                                    machine['isolated'] = False
                            else:
                                unisolation_results.append({
                                    "machine": machine_name,
                                    "success": True,
                                    "was_already_unisolated": True
                                })
                        
                        # Show results
                        st.write("Un-isolation results:")
                        for result in unisolation_results:
                            if result["was_already_unisolated"]:
                                st.info(f"Machine {result['machine']} was already not isolated.")
                            elif result["success"]:
                                st.success(f"Machine {result['machine']} un-isolated successfully!")
                            else:
                                st.error(f"Failed to un-isolate machine: {result['machine']}")
                        
                        if all(result["success"] for result in unisolation_results):
                            st.success("All selected machines have been un-isolated successfully!")
                            st.rerun()
            
            # Custom remediation actions
            st.subheader("Custom Remediation Actions")
            
            # Remediation type selection
            remediation_type = st.radio(
                "Select remediation action type:",
                ["QUARANTINE_FILE", "KILL_PROCESS", "DELETE_REGISTRY_KEY", "BLOCK_FILE"],
                horizontal=True
            )
            
            # Input fields based on remediation type
            target_name = st.text_input("Target name (file, process, registry key)")
            target_id = st.text_input("Target ID (if known)", value=f"auto-generated-{int(time.time())}")
            
            # Action execution button for all selected machines
            if st.button("Execute Remediation on All Selected Machines"):
                if target_name:
                    remediation_results = []
                    with st.spinner(f"Executing {remediation_type} action on {len(selected_machines)} machines..."):
                        for machine in selected_machines:
                            machine_id = machine.get('guid', '')
                            machine_name = machine.get('displayName', 'Unknown')
                            
                            success, response = perform_remediation_action(
                                st.session_state.session,
                                remediation_type,
                                target_name,
                                target_id,
                                machine_name,
                                machine_id
                            )
                            
                            remediation_results.append({
                                "machine": machine_name,
                                "success": success
                            })
                            
                            if success:
                                # Record the action
                                action_record = {
                                    "malop_id": malop_id,
                                    "malop_name": selected_malop,
                                    "machine": machine_name,
                                    "action_type": remediation_type,
                                    "target": target_name,
                                    "executed_at": datetime.now().strftime('%d/%m/%Y at %H:%M:%S'),
                                    "status": "Completed"
                                }
                                
                                # Store action history
                                if not hasattr(st.session_state, 'remediation_history'):
                                    st.session_state.remediation_history = []
                                
                                st.session_state.remediation_history.append(action_record)
                        
                        # Show results
                        st.write("Remediation action results:")
                        for result in remediation_results:
                            if result["success"]:
                                st.success(f"Remediation on {result['machine']} completed successfully!")
                            else:
                                st.error(f"Failed to execute remediation on {result['machine']}")
                        
                        if all(result["success"] for result in remediation_results):
                            st.success(f"Remediation action {remediation_type} executed successfully on all selected machines!")
                else:
                    st.warning("Please enter a target name before executing the action")
        else:
            st.warning("Please select at least one machine from the list above to perform remediation actions")
        
        # Scheduling options
        st.subheader("Scheduling")
        
        schedule_option = st.radio(
            "When to execute",
            ["Immediately", "Schedule for later"]
        )
        
        if schedule_option == "Schedule for later":
            col1, col2 = st.columns(2)
            with col1:
                scheduled_date = st.date_input("Date", datetime.now().date())
            with col2:
                scheduled_time = st.time_input("Time", datetime.now().time())
            
            # Combine date and time
            scheduled_datetime = datetime.combine(scheduled_date, scheduled_time)
            st.info(f"The response will be executed on {scheduled_datetime.strftime('%d/%m/%Y at %H:%M')}")
        
        # Remediation notes
        st.subheader("Remediation Notes")
        remediation_notes = st.text_area("Add notes or comments about this remediation", height=100)
        
        # Remediation history
        st.markdown("---")
        st.subheader("Remediation History")
        
        if hasattr(st.session_state, 'remediation_history') and st.session_state.remediation_history:
            # Convert history to DataFrame for tabular display
            history_data = []
            for record in st.session_state.remediation_history:
                history_data.append({
                    "Malop": record.get("malop_name", "").split(" (")[0],
                    "Machine": record.get("machine", "N/A"),
                    "Action Type": record.get("action_type", "N/A"),
                    "Target": record.get("target", "N/A"),
                    "Executed at": record.get("executed_at", ""),
                    "Status": record.get("status", "")
                })
            
            history_df = pd.DataFrame(history_data)
            st.dataframe(history_df, use_container_width=True)
            
            # Option to export history
            if st.button("Export remediation history"):
                export_path = "reports/remediation_history.csv"
                os.makedirs(os.path.dirname(export_path), exist_ok=True)
                history_df.to_csv(export_path, index=False)
                st.success(f"History exported successfully to {export_path}")
            
            # NOUVELLE PARTIE: Generation avancée de rapport d'incident
            if st.button("Generate incident report"):
                st.info("Generating incident report...")
                
                # Create a directory for reports if it doesn't exist
                os.makedirs("reports/incidents", exist_ok=True)
                
                # Report filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                report_filename = f"incident_report_{timestamp}.pdf"
                report_path = f"reports/incidents/{report_filename}"
                
                # Create PDF report using FPDF
                class IncidentReportPDF(FPDF):
                    def header(self):
                        # Logo
                        try:
                            self.image("logo.png", 10, 8, 33)  # Remplacer par le chemin de votre logo
                        except:
                            pass  # Continue if logo not found
                        # Arial bold 15
                        self.set_font('Arial', 'B', 15)
                        # Move to the right
                        self.cell(80)
                        # Title
                        self.cell(30, 10, 'SECURITY INCIDENT REPORT', 0, 0, 'C')
                        # Line break
                        self.ln(20)
                        
                    def footer(self):
                        # Position at 1.5 cm from bottom
                        self.set_y(-15)
                        # Arial italic 8
                        self.set_font('Arial', 'I', 8)
                        # Page number
                        self.cell(0, 10, 'Page ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')
                        
                # Instantiate PDF document
                pdf = IncidentReportPDF()
                pdf.alias_nb_pages()
                pdf.add_page()
                pdf.set_font('Arial', '', 12)
                
                # Report header
                pdf.set_font('Arial', 'B', 14)
                pdf.cell(0, 10, 'INCIDENT REPORT', 0, 1, 'C')
                pdf.set_font('Arial', '', 12)
                pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%d/%m/%Y at %H:%M:%S')}", 0, 1)
                pdf.cell(0, 10, f"Incident ID: INC-{timestamp}", 0, 1)
                pdf.ln(5)
                
                # Executive Summary
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, '1. EXECUTIVE SUMMARY', 0, 1)
                pdf.set_font('Arial', '', 11)
                incident_summary = f"This report documents the security incident detected by Cybereason EDR and the remediation actions taken. The report includes details about affected systems, malicious activities identified, and response actions executed."
                pdf.multi_cell(0, 7, incident_summary)
                pdf.ln(5)
                
                # Incident Details
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, '2. INCIDENT DETAILS', 0, 1)
                
                # If we have a selected malop, include its details
                if selected_malop_data:
                    pdf.set_font('Arial', 'B', 11)
                    pdf.cell(0, 7, "Malop Information:", 0, 1)
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(40, 7, "Detection Type:", 0, 0)
                    pdf.cell(0, 7, f"{selected_malop_data.get('detectionType', 'Unknown')}", 0, 1)
                    pdf.cell(40, 7, "Severity:", 0, 0)
                    pdf.cell(0, 7, f"{selected_malop_data.get('severity', 'Unknown')}", 0, 1)
                    pdf.cell(40, 7, "Priority:", 0, 0)
                    pdf.cell(0, 7, f"{selected_malop_data.get('priority', 'Unknown')}", 0, 1)
                    pdf.cell(40, 7, "Status:", 0, 0)
                    pdf.cell(0, 7, f"{selected_malop_data.get('status', 'Unknown')}", 0, 1)
                    
                    creation_time = selected_malop_data.get('creationTime', 0)
                    if creation_time:
                        pdf.cell(40, 7, "Creation Date:", 0, 0)
                        pdf.cell(0, 7, f"{datetime.fromtimestamp(creation_time/1000).strftime('%Y-%m-%d %H:%M')}", 0, 1)
                    
                    # MITRE ATT&CK Information
                    mitre_tactics = selected_malop_data.get('mitreTactics', [])
                    if mitre_tactics:
                        pdf.ln(3)
                        pdf.set_font('Arial', 'B', 11)
                        pdf.cell(0, 7, "MITRE ATT&CK Tactics:", 0, 1)
                        pdf.set_font('Arial', '', 10)
                        for tactic in mitre_tactics:
                            pdf.cell(0, 7, f"- {tactic}", 0, 1)
                    
                    mitre_techniques = selected_malop_data.get('mitreTechniques', [])
                    if mitre_techniques:
                        pdf.ln(3)
                        pdf.set_font('Arial', 'B', 11)
                        pdf.cell(0, 7, "MITRE ATT&CK Techniques:", 0, 1)
                        pdf.set_font('Arial', '', 10)
                        for technique in mitre_techniques:
                            pdf.cell(0, 7, f"- {technique}", 0, 1)
                else:
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(0, 7, "No specific Malop information available.", 0, 1)
                
                pdf.ln(5)
                
                # Affected Systems
                pdf.set_font('Arial', 'B', 12)
                pdf.add_page()
                pdf.cell(0, 10, '3. AFFECTED SYSTEMS', 0, 1)
                
                # If we have machines information
                if machines:
                    pdf.set_font('Arial', '', 10)
                    for i, machine in enumerate(machines):
                        pdf.set_font('Arial', 'B', 11)
                        pdf.cell(0, 7, f"Machine {i+1}: {machine.get('displayName', 'Unknown')}", 0, 1)
                        pdf.set_font('Arial', '', 10)
                        pdf.cell(40, 7, "Status:", 0, 0)
                        pdf.cell(0, 7, "Online" if machine.get('connected') else "Offline", 0, 1)
                        pdf.cell(40, 7, "Isolation Status:", 0, 0)
                        pdf.cell(0, 7, "Isolated" if machine.get('isolated') else "Not isolated", 0, 1)
                        pdf.cell(40, 7, "OS Type:", 0, 0)
                        pdf.cell(0, 7, f"{machine.get('osType', 'Unknown')}", 0, 1)
                        pdf.ln(3)
                else:
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(0, 7, "No information about affected systems available.", 0, 1)
                
                # Remediation Actions
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, '4. REMEDIATION ACTIONS TAKEN', 0, 1)
                
                if hasattr(st.session_state, 'remediation_history') and st.session_state.remediation_history:
                    pdf.set_font('Arial', '', 10)
                    for i, record in enumerate(st.session_state.remediation_history):
                        pdf.set_font('Arial', 'B', 10)
                        pdf.cell(0, 7, f"Action {i+1}:", 0, 1)
                        pdf.set_font('Arial', '', 10)
                        pdf.cell(50, 7, "Malop:", 0, 0)
                        pdf.cell(0, 7, f"{record.get('malop_name', '').split(' (')[0]}", 0, 1)
                        pdf.cell(50, 7, "Machine:", 0, 0)
                        pdf.cell(0, 7, f"{record.get('machine', 'N/A')}", 0, 1)
                        pdf.cell(50, 7, "Action Type:", 0, 0)
                        pdf.cell(0, 7, f"{record.get('action_type', 'N/A')}", 0, 1)
                        if 'target' in record:
                            pdf.cell(50, 7, "Target:", 0, 0)
                            pdf.cell(0, 7, f"{record.get('target', 'N/A')}", 0, 1)
                        pdf.cell(50, 7, "Executed at:", 0, 0)
                        pdf.cell(0, 7, f"{record.get('executed_at', '')}", 0, 1)
                        pdf.cell(50, 7, "Status:", 0, 0)
                        pdf.cell(0, 7, f"{record.get('status', '')}", 0, 1)
                        pdf.ln(3)
                else:
                    pdf.set_font('Arial', '', 10)
                    pdf.cell(0, 7, "No remediation actions have been recorded.", 0, 1)
                
                # Notes and Additional Information
                pdf.add_page()
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, '5. NOTES AND ADDITIONAL INFORMATION', 0, 1)
                
                pdf.set_font('Arial', '', 10)
                if remediation_notes.strip():
                    pdf.multi_cell(0, 7, remediation_notes)
                else:
                    pdf.cell(0, 7, "No additional notes provided.", 0, 1)
                
                # Recommendations
                pdf.ln(7)
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, '6. RECOMMENDATIONS', 0, 1)
                pdf.set_font('Arial', '', 10)
                
                # Default recommendations based on common security practices
                recommendations = [
                    "Perform a full system scan on all affected machines to identify any remaining threats.",
                    "Update all security software and operating systems to the latest versions.",
                    "Review and strengthen access controls for affected systems.",
                    "Consider implementing additional security monitoring for affected systems.",
                    "Conduct user awareness training to prevent similar incidents.",
                    "Review and update incident response procedures based on lessons learned."
                ]
                
                for rec in recommendations:
                    pdf.cell(0, 7, f"- {rec}", 0, 1)
                
                # Signatures
                pdf.ln(15)
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(0, 10, '7. SIGNATURES', 0, 1)
                
                pdf.line(20, pdf.get_y() + 20, 90, pdf.get_y() + 20)
                pdf.line(120, pdf.get_y() + 20, 190, pdf.get_y() + 20)
                
                pdf.set_y(pdf.get_y() + 25)
                pdf.cell(90, 10, 'Security Analyst', 0, 0, 'C')
                pdf.cell(30, 10, '', 0, 0)
                pdf.cell(70, 10, 'Security Manager', 0, 1, 'C')
                
                # Save the PDF
                pdf.output(report_path)
                
                # Create a download button for the generated PDF
                with open(report_path, "rb") as file:
                    pdf_bytes = file.read()
                
                # Base64 encode the PDF for download
                b64_pdf = base64.b64encode(pdf_bytes).decode()
                href = f'<a href="data:application/pdf;base64,{b64_pdf}" download="{report_filename}">Click here to download the PDF report</a>'
                
                st.success(f"Incident report generated successfully!")
                st.markdown(href, unsafe_allow_html=True)
        else:
            st.info("No remediation history available.")
        
        # Decision Rules History section
        st.markdown("---")
        st.subheader("Decision Rules History")
        
        # Initialiser l'historique des règles si ce n'est pas déjà fait
        if not hasattr(st.session_state, 'rules_history'):
            st.session_state.rules_history = []
        
        # Afficher l'historique s'il existe
        if st.session_state.rules_history:
            rules_history_df = pd.DataFrame(st.session_state.rules_history)
            st.dataframe(rules_history_df, use_container_width=True)
            
            # Option pour exporter l'historique
            if st.button("Exporter l'historique des règles"):
                export_path = "reports/rules_history.csv"
                os.makedirs(os.path.dirname(export_path), exist_ok=True)
                rules_history_df.to_csv(export_path, index=False)
                st.success(f"Historique exporté avec succès vers {export_path}")
        else:
            st.info("Aucun historique de décision automatisée disponible.")
    else:
        # If no Malop has been retrieved, display a message
        st.warning("Please first retrieve Malops in the 'Retrieve Malops' tab.")
        
        # Button to access the Malops tab
        if st.button("Go to Retrieve Malops tab"):
            st.session_state.active_tab = "Retrieve Malops"
            st.rerun()
#tab4

with tab4:
    st.header("Automated Response NIST")

    if "session" not in st.session_state or "malops_data" not in st.session_state:
        st.warning("⚠️ Session ou Malops non initialisés. Veuillez d'abord utiliser l'onglet 'Retrieve Malops'.")
        st.stop()
    
    # Ajout de l'information sur le statut de validation
    st.info("⚠️ Seuls les Malops avec statut de validation 'Confirmed' seront traités automatiquement.")

    # Affichage des règles disponibles
    with st.expander("Règles de décision disponibles", expanded=True):
        rules = define_decision_rules()  # On suppose que les règles sont définies ailleurs dans l'app
        
        active_rules = []
        for i, rule in enumerate(rules):
            col1, col2 = st.columns([3, 1])
            
            with col1:
                st.subheader(f"{i+1}. {rule['name']}")
                st.write(f"Description: {rule['description']}")
                st.write(f"Actions: {', '.join(rule['actions'])}")
            
            with col2:
                # Option pour activer/désactiver chaque règle
                key = f"rule_{i}_active"
                if key not in st.session_state:
                    st.session_state[key] = True  # Par défaut activé
                
                is_active = st.toggle("Activé", st.session_state[key], key=f"toggle_rule_{i}")
                st.session_state[key] = is_active
                
                if is_active:
                    active_rules.append(rule)

    if not active_rules:
        st.info("Aucune règle active. Activez des règles dans l'onglet 'Remediation & Response' pour activer le mode auto.")
        st.stop()

    st.info("⏱️ Analyse automatique des Malops toutes les 5 minutes. Cette page se rafraîchit automatiquement.")

    # Affichage des statuts de validation actuels
    if hasattr(st.session_state, 'malops_data') and st.session_state.malops_data:
        malops = st.session_state.malops_data["data"]["data"]
        
        # Compter les malops par statut de validation
        validation_counts = {"Confirmed": 0, "Suspect": 0, "False Positive": 0}
        for malop in malops:
            malop_id = malop.get("guid", "N/A")
            status = get_validation_status(malop_id)
            validation_counts[status] = validation_counts.get(status, 0) + 1
        
        # Afficher les compteurs
        st.subheader("Statuts de validation")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Confirmés", validation_counts["Confirmed"], 
                      delta=None, delta_color="normal")
        with col2:
            st.metric("Suspects", validation_counts["Suspect"], 
                      delta=None, delta_color="normal")
        with col3:
            st.metric("Faux Positifs", validation_counts["False Positive"], 
                      delta=None, delta_color="normal")
    
    # Appliquer l'analyse automatique des règles
    st.subheader("🧠 Application automatique des règles")
    
    if hasattr(st.session_state, 'malops_data') and st.session_state.malops_data:
        with st.spinner("Exécution en cours..."):
            results = analyze_rules_automatically(
                st.session_state.malops_data,
                st.session_state.session,
                active_rules
            )
            if results:
                for res in results:
                    st.success(f"[{res.get('machine', 'Unknown')}] → {res.get('malop_name', 'Unknown Malop')} : {res.get('actions', 'No actions')}")
            else:
                st.info("✅ Aucune menace nécessitant une action immédiate ou aucun Malop confirmé.")
    else:
        st.warning("Veuillez d'abord récupérer les Malops dans l'onglet 'Retrieve Malops'.")
    
    # Section de gestion des statuts de validation (optionnelle)
    with st.expander("Gestion des statuts de validation", expanded=False):
        st.subheader("Modifier les statuts de validation")
        
        if hasattr(st.session_state, 'malops_data') and st.session_state.malops_data:
            malops = st.session_state.malops_data["data"]["data"]
            
            # Tableau récapitulatif des statuts
            validation_table = []
            for malop in malops:
                malop_id = malop.get("guid", "N/A")
                validation_table.append({
                    "ID": malop_id,
                    "Nom": malop.get("displayName", "Unknown"),
                    "Sévérité": malop.get("severity", "Unknown"),
                    "Statut validation": get_validation_status(malop_id)
                })
            
            st.dataframe(pd.DataFrame(validation_table), use_container_width=True)
            
            # Formulaire rapide de mise à jour
            col1, col2 = st.columns(2)
            with col1:
                malop_to_update = st.selectbox(
                    "Sélectionner un Malop",
                    options=[m.get("guid", "N/A") for m in malops],
                    format_func=lambda x: next((m.get("displayName", "Unknown") for m in malops if m.get("guid") == x), x)
                )
            
            with col2:
                new_status = st.radio(
                    "Nouveau statut",
                    options=["Suspect", "Confirmed", "False Positive"]
                )
            
            if st.button("Mettre à jour"):
                update_validation_status(malop_to_update, new_status)
                st.success(f"Statut mis à jour pour le Malop {malop_to_update}")
                st.rerun()

    # Rafraîchissement automatique toutes les 5 minutes
    time.sleep(300)
    # st.experimental_rerun()
# Ajouter un pied de page
st.markdown("---")
st.markdown("© 2025 EDR Automation Assistant - Développé Par Anouar Sayah")


