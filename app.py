import streamlit as st
import pandas as pd
import requests
import json
import os
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import time

# Configuration de la page Streamlit
st.set_page_config(page_title="EDR Chatbot Automation", layout="wide")

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


# Fonction pour récupérer les Malops
def get_malops(config):
    print("Starting Malops retrieval...")
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
    malop_state = ""

    query = json.dumps({"search":{},"range":{"from":time_range_start,"to":time_range_end},"pagination":{"pageSize":100,"offset":0},"filter":{"malop":{"status":[malop_state]}}})

    print(f"Sending request to {api_url}...")
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

# Fonction pour afficher le tableau de bord des Malops
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
    
    # Graphique des statuts
  
    
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
    
    # Tableau détaillé des Malops
    st.subheader("Malops List")
    
    # Convertir les données en DataFrame
    malops_table = []
    for malop in malops:
        machines_list = ", ".join([m.get("displayName", "Unknown") for m in malop.get("machines", [])])
        
        malops_table.append({
            "ID": malop.get("guid", "N/A"),
            "Name": malop.get("displayName", "Unknown"),
            "Detection Type": malop.get("detectionType", "Unknown"),
            "Severity": malop.get("severity", "Unknown"),
            "Priority": malop.get("priority", "Unknown"),
            "Status": malop.get("status", "Unknown"),
            "Creation Date": datetime.fromtimestamp(malop.get("creationTime", 0)/1000).strftime("%Y-%m-%d %H:%M"),
            "Affected Machines": machines_list
        })
    
    malops_df = pd.DataFrame(malops_table)
    st.dataframe(malops_df, use_container_width=True)
    
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
   
    

# Interface Streamlit principale
st.image("logo/2.png", width=100)
st.title("EDR Chatbot Automation")

# Navigation par onglets - 4 onglets (après fusion)
tab1, tab2, tab3, tab4 = st.tabs([
    "Machine Analysis",
    "Vulnerability Management",  
    "Retrieve Malops", 
    "Remediation & Response"
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
                
                with action_col2:
                    if st.button("Analyze Offline Machines"):
                        st.info("Analyzing offline machines...")
                        # Ici, on pourrait ajouter une fonctionnalité pour analyser pourquoi 
                        # ces machines sont hors ligne (problèmes réseau, EDR désinstallé, etc.)
                        st.warning("Feature under development")
            else:
                st.warning("No online machines found.")

# Onglet 2: Gestion des vulnérabilités
with tab2:
    st.header("Vulnerability Management")
    st.info("Feature under development")

# Onglet 3: Retrieve Malops
with tab3:
    st.header("Malops Dashboard")
    
    # Options de filtrage
    st.subheader("Filter Options")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.multiselect(
            "Filter by severity",
            [ "High", "Medium", "Low"],
            default=["Low","Medium",  "High"]
        )
    
    with col2:
        status_filter = st.radio(
            "Status",
            ["Active", "Remediated", "Closed", "Excluded", "All"],
            index=0
        )
    
    with col3:
        priority_filter = st.multiselect(
            "Filter by priority",
            ["HIGH", "MEDIUM", "LOW"],
            default=["HIGH"]
        )
    
    # Bouton pour récupérer les Malops
    if st.button("Retrieve and analyze Malops"):
        with st.spinner("Retrieving and analyzing Malops..."):
            try:
                # Récupérer les données des Malops
                config = load_config()
                malops_data, session = get_malops(config)
                
                if malops_data:
                    # Analyser les données
                    analysis_results = analyze_malops(malops_data)
                    
                    # Stocker les résultats dans l'état de session
                    st.session_state.malops_data = malops_data
                    st.session_state.malops_analysis = analysis_results
                    
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
# Tab 4: Remediation & Response
with tab4:
    st.header("Remediation & Response")
    
    if hasattr(st.session_state, 'malops_data') and st.session_state.malops_data:
        # Create two sections with expanders to organize content
        with st.expander("Malop Selection and Information", expanded=True):
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
                        
                        # Added a selection column for machines
                        selected_machine = None
                        if len(machines) > 0:
                            machine_options = {m.get('displayName', 'Unknown'): m for m in machines}
                            selected_machine_name = st.selectbox("Select machine for remediation", list(machine_options.keys()))
                            selected_machine = machine_options[selected_machine_name]
                        
                        machine_data = []
                        for machine in machines:
                            is_selected = selected_machine and machine.get('displayName') == selected_machine.get('displayName')
                            machine_data.append({
                                "Name": machine.get('displayName', 'Unknown'),
                                "Status": "🟢 Online" if machine.get('connected') else "🔴 Offline",
                                "Isolation": "🔒 Isolated" if machine.get('isolated') else "🔓 Not isolated",
                                "OS": machine.get('osType', 'Unknown'),
                                "Selected": "✅" if is_selected else ""
                            })
                        
                        st.dataframe(pd.DataFrame(machine_data))
                        
                        # Store the selected machine in session state for remediation
                        if selected_machine:
                            st.session_state.selected_machine = selected_machine
                    
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
        
        # Section for remediation actions
        with st.expander("Remediation Actions", expanded=True):
            st.subheader("Response Configuration")
            
            # Check if we have a selected machine
            if hasattr(st.session_state, 'selected_machine') and st.session_state.selected_machine:
                machine = st.session_state.selected_machine
                machine_id = machine.get('guid', '')
                machine_name = machine.get('displayName', 'Unknown')
                
                # Show machine isolation status and controls
                is_isolated = machine.get('isolated', False)
                isolation_status = "🔒 Isolated" if is_isolated else "🔓 Not isolated"
                
                st.write(f"**Machine:** {machine_name}")
                st.write(f"**Isolation status:** {isolation_status}")
                
                # Isolation controls
                col1, col2 = st.columns(2)
                with col1:
                    if not is_isolated and st.button("Isolate Machine"):
                        with st.spinner("Isolating machine..."):
                            success, response = isolate_machine(
                                st.session_state.session, 
                                machine_id, 
                                malop_id
                            )
                            if success:
                                st.success(f"Machine {machine_name} isolated successfully!")
                                # Update the machine's isolation status
                                st.session_state.selected_machine['isolated'] = True
                                st.rerun()
                            else:
                                st.error(f"Failed to isolate machine: {machine_name}")
                
                with col2:
                    if is_isolated and st.button("Un-isolate Machine"):
                        with st.spinner("Un-isolating machine..."):
                            success, response = unisolate_machine(
                                st.session_state.session, 
                                machine_id, 
                                malop_id
                            )
                            if success:
                                st.success(f"Machine {machine_name} un-isolated successfully!")
                                # Update the machine's isolation status
                                st.session_state.selected_machine['isolated'] = False
                                st.rerun()
                            else:
                                st.error(f"Failed to un-isolate machine: {machine_name}")
                
                # Remediation action selection
                st.subheader("Remediation Actions")
                
                # Response options
                response_type = st.radio(
                    "Response type",
                    ["Standard response", "Custom response"]
                )
                
                if response_type == "Standard response":
                    st.info("Standard response includes terminating malicious processes and quarantining suspicious files.")
                    
                    if st.button("Run Standard Response"):
                        with st.spinner("Executing standard response..."):
                            # Execute kill processes action (standard)
                            success1, response1 = perform_remediation_action(
                                st.session_state.session,
                                "KILL_PROCESS",
                                "malicious_process",
                                f"auto-kill-{int(time.time())}",
                                machine_name,
                                machine_id
                            )
                            
                            # Execute quarantine files action (standard)
                            success2, response2 = perform_remediation_action(
                                st.session_state.session,
                                "QUARANTINE_FILE",
                                "suspicious_file",
                                f"auto-quarantine-{int(time.time())}",
                                machine_name,
                                machine_id
                            )
                            
                            if success1 and success2:
                                st.success("Standard response executed successfully!")
                                
                                # Record the action
                                action_record = {
                                    "malop_id": malop_id,
                                    "malop_name": selected_malop,
                                    "machine": machine_name,
                                    "action_type": "Standard Response (KILL_PROCESS, QUARANTINE_FILE)",
                                    "executed_at": datetime.now().strftime('%d/%m/%Y at %H:%M:%S'),
                                    "status": "Completed"
                                }
                                
                                # Store action history
                                if not hasattr(st.session_state, 'remediation_history'):
                                    st.session_state.remediation_history = []
                                
                                st.session_state.remediation_history.append(action_record)
                            else:
                                st.error("Failed to execute standard response")
                else:
                    # Custom response options with action descriptions
                    st.info("Configure your custom response below.")
                    
                    # Remediation type selection
                    remediation_type = st.radio(
                        "Select remediation action type:",
                        ["QUARANTINE_FILE", "KILL_PROCESS", "DELETE_REGISTRY_KEY", "BLOCK_FILE"],
                        horizontal=True
                    )
                    
                    # Input fields based on remediation type
                    target_name = st.text_input("Target name (file, process, registry key)")
                    target_id = st.text_input("Target ID (if known)", value=f"auto-generated-{int(time.time())}")
                    
                    # Action execution button
                    if st.button("Execute Remediation Action"):
                        if target_name:
                            with st.spinner(f"Executing {remediation_type} action..."):
                                success, response = perform_remediation_action(
                                    st.session_state.session,
                                    remediation_type,
                                    target_name,
                                    target_id,
                                    machine_name,
                                    machine_id
                                )
                                
                                if success:
                                    st.success(f"Remediation action {remediation_type} executed successfully!")
                                    
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
                                else:
                                    st.error(f"Failed to execute remediation action: {remediation_type}")
                        else:
                            st.warning("Please enter a target name before executing the action")
            else:
                st.warning("Please select a machine from the list above to perform remediation actions")
            
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
        with st.expander("Remediation History", expanded=False):
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
                
                # Option to generate incident report
                if st.button("Generate incident report"):
                    st.info("Generating incident report...")
                    
                    # Create a directory for reports if it doesn't exist
                    os.makedirs("reports/incidents", exist_ok=True)
                    
                    # Report filename
                    report_filename = f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    report_path = f"reports/incidents/{report_filename}"
                    
                    # Report content
                    report_content = f"""
SECURITY INCIDENT REPORT
==============================
Report date: {datetime.now().strftime('%d/%m/%Y at %H:%M:%S')}

REMEDIATION HISTORY
------------------
{history_df.to_string(index=False)}

NOTES
-----
{remediation_notes}

This report was automatically generated by EDR Chatbot Automation.
                    """
                    
                    # Write the report to a file
                    with open(report_path, "w") as f:
                        f.write(report_content)
                    
                    st.success(f"Incident report generated successfully: {report_path}")
                    
                    # Display report content
                    with st.expander("View report content"):
                        st.text(report_content)
            else:
                st.info("No remediation history available.")
    else:
        # If no Malop has been retrieved, display a message
        st.warning("Please first retrieve Malops in the 'Retrieve Malops' tab.")
        
        # Button to access the Malops tab
        if st.button("Go to Retrieve Malops tab"):
            st.session_state.active_tab = "Retrieve Malops"
            st.rerun()

# Ajouter un pied de page
st.markdown("---")
st.markdown("© 2025 EDR Chatbot Automation - Développé Par Anouar Sayah")