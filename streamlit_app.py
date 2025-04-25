#!/usr/bin/env python3
import streamlit as st
from cyber_initiative_update import CyberScanner
import os
from datetime import datetime

# Configure page
st.set_page_config(
    page_title="Cyber Initiative AI Scanner",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .report-title {
        color: #1e3a8a;
        font-size: 2.5em;
        text-align: center;
    }
    .severity-critical {
        color: #dc2626;
        font-weight: bold;
    }
    .severity-high {
        color: #ea580c;
    }
    .severity-medium {
        color: #d97706;
    }
    .severity-low {
        color: #65a30d;
    }
</style>
""", unsafe_allow_html=True)

def get_business_risk(severity):
    risk_map = {
        "CRITICAL": "Complete system compromise possible",
        "HIGH": "Sensitive data exposure",
        "MEDIUM": "Limited unauthorized access",
        "LOW": "Security best practice violation"
    }
    return risk_map.get(severity, "Potential security weakness")

# Main app
def main():
    st.markdown('<h1 class="report-title">Cyber Initiative AI Scanner</h1>', unsafe_allow_html=True)
    
    # URL input
    target_url = st.text_input("Enter target URL (e.g., http://example.com)", "http://testfire.net")
    
    # Scan options
    col1, col2 = st.columns(2)
    with col1:
        max_depth = st.slider("Scan depth (pages)", 1, 5, 2)
    with col2:
        scan_button = st.button("🚀 Run Security Scan")
    
    if scan_button:
        with st.spinner("Scanning website..."):
            # Initialize scanner
            scanner = CyberScanner()
            
            # Run scan
            scanner.crawl(target_url, max_depth=max_depth)
            
            # Generate reports
            reports_dir = "reports"
            os.makedirs(reports_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Display results
            st.success("Scan completed!")
            
            # Results summary
            st.subheader("📊 Scan Summary")
            col1, col2, col3 = st.columns(3)
            col1.metric("Pages Scanned", len(scanner.visited))
            col2.metric("Vulnerabilities Found", len(scanner.findings))
            col3.metric("Scan Duration", f"{(datetime.now() - scanner.start_time).total_seconds():.2f} sec")
            
            # Vulnerabilities found
            if scanner.findings:
                st.subheader("🚨 Vulnerabilities Found")
                for idx, finding in enumerate(scanner.findings.values(), 1):
                    severity_class = f"severity-{finding['severity'].lower()}"
                    business_risk = get_business_risk(finding['severity'])
                    
                    with st.expander(f"{idx}. [{finding['severity']}] {finding['vulnerability']}", expanded=True):
                        st.markdown(f"""
                        <div class="{severity_class}">
                        <strong>URL:</strong> {finding['url']}<br>
                        <strong>Evidence:</strong> {finding.get('evidence', 'N/A')[:200]}...<br>
                        <strong>Business Risk:</strong> {business_risk}<br>
                        <strong>Recommendation:</strong> {finding['advice']}
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.success("✅ No vulnerabilities found!")
            
            # Report download section
            st.subheader("📁 Download Reports")
            
            # Generate reports
            scanner.generate_reports()
            
            # Display download buttons
            col1, col2, col3 = st.columns(3)
            with col1:
                with open("reports/cyber_report.pdf", "rb") as f:
                    st.download_button(
                        label="Download PDF Report",
                        data=f,
                        file_name=f"cyber_report_{timestamp}.pdf",
                        mime="application/pdf"
                    )
            with col2:
                with open("reports/cyber_report.html", "rb") as f:
                    st.download_button(
                        label="Download HTML Report",
                        data=f,
                        file_name=f"cyber_report_{timestamp}.html",
                        mime="text/html"
                    )
            with col3:
                with open("reports/cyber_report.json", "rb") as f:
                    st.download_button(
                        label="Download JSON Report",
                        data=f,
                        file_name=f"cyber_report_{timestamp}.json",
                        mime="application/json"
                    )

if __name__ == "__main__":
    main()
