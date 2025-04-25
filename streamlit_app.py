#!/usr/bin/env python3
import streamlit as st
from cyber_initiative_update import CyberScanner
from datetime import datetime
import os

# Configure page (your exact config)
st.set_page_config(
    page_title="Cyber Initiative AI Scanner",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Your exact CSS
st.markdown("""
<style>
    .report-title {
        color: #1e3a8a;
        font-size: 2.5em;
        text-align: center;
        margin-bottom: 20px;
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
    .stDownloadButton button {
        width: 100%;
        transition: all 0.2s ease;
    }
    .stDownloadButton button:hover {
        transform: scale(1.02);
    }
    .st-emotion-cache-1y4p8pa {
        padding: 2rem 1.5rem;
    }
</style>
""", unsafe_allow_html=True)

def get_business_risk(severity):
    risk_map = {
        "CRITICAL": "Complete system compromise and data theft possible",
        "HIGH": "Could enable attackers to steal sensitive data",
        "MEDIUM": "May allow limited unauthorized access",
        "LOW": "Security best practice violation"
    }
    return risk_map.get(severity, "Potential security weakness")

def handle_reports(scanner, timestamp):
    """Dual-mode report handling that works everywhere"""
    reports = scanner.generate_reports()
    
    # Local filesystem saving (only if not in cloud)
    if not os.environ.get("STREAMLIT_CLOUD"):
        os.makedirs("reports", exist_ok=True)
        if reports["pdf"]:
            with open(f"reports/cyber_report_{timestamp}.pdf", "wb") as f:
                f.write(reports["pdf"])
        with open(f"reports/cyber_report_{timestamp}.json", "w") as f:
            f.write(reports["json"])
        with open(f"reports/cyber_report_{timestamp}.html", "w") as f:
            f.write(reports["html"])
    
    return reports

def main():
    st.markdown('<h1 class="report-title">Cyber Initiative AI Scanner</h1>', unsafe_allow_html=True)
    
    # Your exact sidebar config
    with st.sidebar:
        st.header("Configuration")
        target_url = st.text_input(
            "Target URL",
            value="http://testfire.net",
            help="Enter the website URL to scan"
        )
        max_depth = st.slider(
            "Scan Depth (pages)",
            min_value=1,
            max_value=5,
            value=2,
            help="How many pages deep to crawl"
        )
        scan_button = st.button(
            "🚀 Run Full Security Scan",
            type="primary",
            use_container_width=True
        )
        st.markdown("---")
        st.markdown("**Note:** This is a demo scanner. Real-world scanning requires proper authorization.")

    if scan_button:
        with st.spinner(f"Scanning {target_url} (depth: {max_depth})..."):
            scanner = CyberScanner()
            scanner.crawl(target_url, max_depth=max_depth)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Your exact results display
            st.success(f"✅ Scan completed in {(datetime.now() - scanner.start_time).total_seconds():.2f} seconds")
            
            col1, col2 = st.columns(2)
            col1.metric("Pages Scanned", len(scanner.visited))
            col2.metric("Vulnerabilities Found", len(scanner.findings))
            
            if scanner.findings:
                st.subheader("🚨 Security Findings", divider="red")
                for idx, finding in enumerate(scanner.findings.values(), 1):
                    with st.expander(
                        f"{idx}. [{finding['severity']}] {finding['vulnerability']}",
                        expanded=(idx == 1)
                    ):
                        st.markdown(f"""
                        <div class="severity-{finding['severity'].lower()}">
                            <strong>🔗 URL:</strong> {finding['url']}<br>
                            <strong>📌 Evidence:</strong> <code>{finding.get('evidence', 'N/A')[:200]}</code><br>
                            <strong>⚠️ Business Risk:</strong> {get_business_risk(finding['severity'])}<br>
                            <strong>🛡 Recommendation:</strong> {finding['advice']}
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.success("🎉 No vulnerabilities found!", icon="✅")
            
            # Report handling with dual-mode support
            st.subheader("📥 Download Full Reports", divider="blue")
            reports = handle_reports(scanner, timestamp)
            
            # Your exact download buttons (now cloud-compatible)
            if reports["pdf"]:
                st.download_button(
                    label="📄 Download PDF Report",
                    data=reports["pdf"],
                    file_name=f"cyber_report_{timestamp}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            
            if reports["json"]:
                st.download_button(
                    label="📊 Download JSON Report",
                    data=reports["json"],
                    file_name=f"cyber_report_{timestamp}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            if reports["html"]:
                st.download_button(
                    label="🌐 Download HTML Report",
                    data=reports["html"].encode(),
                    file_name=f"cyber_report_{timestamp}.html",
                    mime="text/html",
                    use_container_width=True
                )

if __name__ == "__main__":
    main()
