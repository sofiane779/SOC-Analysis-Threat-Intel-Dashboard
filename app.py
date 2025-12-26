import streamlit as st
import pandas as pd
import re
import requests

# --- PAGE CONFIGURATION ---
# Sets the tab title and the layout to wide mode for a better professional look
st.set_page_config(page_title="SOC Analyzer Pro", page_icon="🛡️", layout="wide")

# --- SIDEBAR CONFIGURATION ---
st.sidebar.title("Settings")
st.sidebar.info("Enter your VirusTotal API key to enable Threat Intelligence features.")
api_key = st.sidebar.text_input("VirusTotal API Key", type="password")

# --- MAIN TITLE ---
st.title("🛡️ SOC Analysis & Threat Intel Dashboard")
st.markdown("---")

# --- VIRUSTOTAL API FUNCTION ---
def check_ip_vt(ip, key):
    """Checks the reputation of an IP address using VirusTotal API v3."""
    if not key:
        return "Missing Key"
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": key}
    
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            # Returns the number of malicious detections vs total engines
            return f"{stats['malicious']}/{sum(stats.values())}"
        elif response.status_code == 401:
            return "Invalid Key"
        else:
            return f"Error {response.status_code}"
    except Exception as e:
        return "Connection Error"

# --- LOG FILE UPLOAD ---
uploaded_file = st.file_uploader("Upload your log file (auth.log, syslog, etc.)", type=['log', 'txt'])

if uploaded_file:
    # Read the file content and decode to string
    content = uploaded_file.read().decode("utf-8")
    
    # REGEX: Search for IPv4 patterns (0.0.0.0 to 255.255.255.255)
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    all_ips = re.findall(ip_pattern, content)

    if all_ips:
        # Data Processing with Pandas
        df = pd.DataFrame(all_ips, columns=['IP Address'])
        ip_counts = df['IP Address'].value_counts().reset_index()
        ip_counts.columns = ['IP Address', 'Count']
        
        # Display Analysis Results
        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("📊 Top Attacking IP Addresses")
            # Visualizing the Top 10 IPs with a bar chart
            st.bar_chart(ip_counts.set_index('IP Address').head(10))

        with col2:
            st.subheader("🚨 Threat Intelligence (Top 5)")
            # Get the top 5 IPs for API checking (to stay within free quota)
            top_5 = ip_counts.head(5).copy()

            if st.button("Check Reputation on VirusTotal"):
                if not api_key:
                    st.error("Please provide a VirusTotal API Key in the sidebar.")
                else:
                    with st.spinner('Querying VirusTotal...'):
                        top_5['VT Score'] = top_5['IP Address'].apply(lambda x: check_ip_vt(x, api_key))
                    st.table(top_5)
            else:
                st.info("Click the button above to fetch security scores.")

        # Full Data Table
        st.markdown("---")
        st.subheader("📋 Full IP Occurrence List")
        st.dataframe(ip_counts, use_container_width=True)
        
    else:
        st.warning("No IP addresses found in the uploaded file. Please check your log format.")

else:
    # Welcome message when no file is uploaded
    st.info("👋 Welcome! Please upload a log file to start the analysis.")