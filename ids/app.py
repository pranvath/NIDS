import streamlit as st
import pandas as pd
import time
import requests

API_URL = "http://127.0.0.1:8000/api/alerts"

st.set_page_config(
    page_title="Real-Time Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Network Intrusion Detection System Dashboard")
st.markdown("Monitoring real-time network traffic and displaying alerted anomalies via FastAPI telemetry.")

# Helper function to generate highlighted headings
def styled_header(text):
    return f"""
    <div style="background-color: #111827; padding: 10px 15px; border-left: 5px solid #3b82f6; border-radius: 4px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.5);">
        <h3 style="margin: 0; font-size: 1.1rem; color: #ffffff; font-weight: 600;">{text}</h3>
    </div>
    """

# Placeholder for real-time updates
placeholder = st.empty()

while True:
    with placeholder.container():
        try:
            response = requests.get(API_URL, timeout=2)
            if response.status_code == 200:
                data = response.json()
                df = pd.DataFrame(data)
                
                if not df.empty:
                    # Top-level metrics
                    col1, col2, col3 = st.columns(3)
                    
                    total_alerts = len(df)
                    high_severity = len(df[df['Severity'] == 'HIGH'])
                    
                    col1.metric("Total API Alerts", total_alerts)
                    col2.metric("High Severity Alerts", high_severity)
                    col3.metric("Unique Attacker IPs", df['Source_IP'].nunique())
                    
                    st.divider()
                    
                    # Columns for charts
                    c1, c2 = st.columns(2)
                    
                    with c1:
                        st.markdown(styled_header("Alert Types Breakdown"), unsafe_allow_html=True)
                        alert_counts = df['Alert_Type'].value_counts()
                        st.bar_chart(alert_counts, color="#FF4B4B") # Red bars for Alerts
                        
                    with c2:
                        st.markdown(styled_header("Top Source IPs (Attackers)"), unsafe_allow_html=True)
                        ip_counts = df['Source_IP'].value_counts().head(5).reset_index()
                        ip_counts.columns = ['Source_IP', 'Count']
                        st.bar_chart(ip_counts, x='Source_IP', y='Count', color='Source_IP')
                    
                    st.markdown(styled_header("Recent API Alerts Log"), unsafe_allow_html=True)
                    # We have already limited records gracefully on the backend!
                    
                    # Style the table headers to be bold and match the dark theme
                    styled_df = df.style.set_table_styles([
                        {'selector': 'th', 'props': [('font-weight', '900 !important'), ('color', '#3b82f6'), ('font-size', '1.05rem'), ('background-color', '#111827')]}
                    ])
                    st.dataframe(styled_df, width='stretch')
                else:
                    st.info("API is online, but zero alerts have been generated into the SQLite database so far.")
            else:
                st.warning(f"Error fetching from API. Status Code: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to FastAPI Backend database server. Ensure you have booted `uvicorn backend.api:app --port 8000`")
        except Exception as e:
            st.error(f"Error parsing dashboard telemetry: {e}")
            
    time.sleep(2)
