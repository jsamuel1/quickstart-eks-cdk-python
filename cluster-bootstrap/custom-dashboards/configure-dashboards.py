#!/usr/bin/env python3

"""
Script to configure Grafana with custom dashboards for advanced metrics visualization.
This script is designed to be run after the EKS cluster with Prometheus and Grafana is deployed.
"""

import os
import json
import sys
import subprocess
import requests
import time
import base64
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin

# Default configuration
GRAFANA_USER = "admin"
GRAFANA_PASSWORD = "prom-operator"
DASHBOARDS_DIR = os.path.dirname(os.path.abspath(__file__))

def get_grafana_url():
    """Get Grafana URL from the Kubernetes service"""
    try:
        # Get the Grafana NLB address
        cmd = ["kubectl", "get", "service", "grafana-nlb", "-n", "kube-system", "-o", "jsonpath={.status.loadBalancer.ingress[0].hostname}"]
        grafana_host = subprocess.check_output(cmd).decode('utf-8').strip()
        
        if not grafana_host:
            print("Error: Could not find Grafana NLB address. Please check if the service is deployed.")
            sys.exit(1)
        
        return f"http://{grafana_host}"
    except subprocess.CalledProcessError as e:
        print(f"Error getting Grafana URL: {e}")
        sys.exit(1)

def wait_for_grafana(grafana_url, max_retries=30, retry_interval=10):
    """Wait for Grafana to become available"""
    print(f"Waiting for Grafana at {grafana_url} to become available...")
    
    for i in range(max_retries):
        try:
            response = requests.get(urljoin(grafana_url, "/api/health"), timeout=5)
            if response.status_code == 200:
                print("Grafana is now available!")
                return True
        except requests.RequestException:
            pass
        
        print(f"Grafana not yet available. Retrying in {retry_interval} seconds... ({i+1}/{max_retries})")
        time.sleep(retry_interval)
    
    print("Timed out waiting for Grafana to become available.")
    return False

def create_dashboard_folder(grafana_url, folder_name="Custom Dashboards"):
    """Create a folder for custom dashboards in Grafana"""
    url = urljoin(grafana_url, "/api/folders")
    payload = {
        "title": folder_name
    }
    
    try:
        response = requests.post(
            url,
            json=payload,
            auth=HTTPBasicAuth(GRAFANA_USER, GRAFANA_PASSWORD)
        )
        
        if response.status_code in [200, 201]:
            folder_data = response.json()
            print(f"Created folder: {folder_name} with ID: {folder_data.get('id')}")
            return folder_data.get('id'), folder_data.get('uid')
        else:
            # Folder might already exist, try to find it
            folders_response = requests.get(
                url,
                auth=HTTPBasicAuth(GRAFANA_USER, GRAFANA_PASSWORD)
            )
            
            if folders_response.status_code == 200:
                folders = folders_response.json()
                for folder in folders:
                    if folder.get('title') == folder_name:
                        print(f"Using existing folder: {folder_name} with ID: {folder.get('id')}")
                        return folder.get('id'), folder.get('uid')
            
            print(f"Failed to create folder. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return None, None
    except requests.RequestException as e:
        print(f"Error creating folder: {e}")
        return None, None

def import_dashboard(grafana_url, dashboard_path, folder_id):
    """Import a dashboard from a JSON file into Grafana"""
    try:
        with open(dashboard_path, 'r') as f:
            dashboard_json = json.load(f)
        
        # Prepare the dashboard for import
        dashboard_json["id"] = None
        
        # Prepare the import payload
        payload = {
            "dashboard": dashboard_json,
            "overwrite": True,
            "folderId": folder_id
        }
        
        url = urljoin(grafana_url, "/api/dashboards/db")
        response = requests.post(
            url,
            json=payload,
            auth=HTTPBasicAuth(GRAFANA_USER, GRAFANA_PASSWORD)
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"Successfully imported dashboard: {os.path.basename(dashboard_path)}")
            print(f"Dashboard URL: {result.get('url')}")
            return True
        else:
            print(f"Failed to import dashboard {os.path.basename(dashboard_path)}. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"Error importing dashboard {os.path.basename(dashboard_path)}: {e}")
        return False

def main():
    """Main function to configure Grafana with custom dashboards"""
    # Get Grafana URL
    grafana_url = get_grafana_url()
    print(f"Grafana URL: {grafana_url}")
    
    # Wait for Grafana to be available
    if not wait_for_grafana(grafana_url):
        print("Exiting due to Grafana availability issues.")
        sys.exit(1)
    
    # Create a folder for custom dashboards
    folder_id, folder_uid = create_dashboard_folder(grafana_url)
    if not folder_id:
        print("Exiting due to folder creation issues.")
        sys.exit(1)
    
    # Find all JSON dashboard files in the current directory
    dashboard_files = [f for f in os.listdir(DASHBOARDS_DIR) if f.endswith('.json')]
    
    if not dashboard_files:
        print(f"No dashboard JSON files found in {DASHBOARDS_DIR}")
        sys.exit(0)
    
    # Import each dashboard
    success_count = 0
    for dashboard_file in dashboard_files:
        dashboard_path = os.path.join(DASHBOARDS_DIR, dashboard_file)
        if import_dashboard(grafana_url, dashboard_path, folder_id):
            success_count += 1
    
    print(f"Imported {success_count} out of {len(dashboard_files)} dashboards successfully.")

if __name__ == "__main__":
    main()