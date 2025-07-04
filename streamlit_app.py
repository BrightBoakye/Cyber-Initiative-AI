#!/usr/bin/env python3
import streamlit as st
from cyber_initiative_update import CyberScanner
from datetime import datetime
from ai_report_generator import generate_ai_summary


# Configure page
st.set_page_config(
    page_title="Cyber Initiative AI Scanner",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
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

def main():
    st.markdown('<h1 class="report-title">Cyber Initiative AI Scanner</h1>', unsafe_allow_html=True)
    
    # Sidebar configuration
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

            # Convert findings to text summary
            scan_summary_text = "\n".join(
                f"[{f['severity']}] {f['vulnerability']} at {f['url']}: {f['advice']}"
                for f in scanner.findings.values()
            )
            
            # Call AI to generate executive summary
            ai_summary = generate_ai_summary(scan_summary_text) if scan_summary_text else \
                "✅ No critical vulnerabilities were found. The system appears secure at this time. Continue regular monitoring and testing."
            
            # Display in UI
            st.subheader("🧠 AI-Powered Executive Summary", divider="blue")
            st.markdown(ai_summary)

            # Display results
            st.success(f"✅ Scan completed in {(datetime.now() - scanner.start_time).total_seconds():.2f} seconds")
            
            # Metrics
            col1, col2 = st.columns(2)
            col1.metric("Pages Scanned", len(scanner.visited))
            col2.metric("Vulnerabilities Found", len(scanner.findings))
            
            # Findings display
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
                            <strong>⚠ Business Risk:</strong> {get_business_risk(finding['severity'])}<br>
                            <strong>🛡 Recommendation:</strong> {finding['advice']}
                        </div>
                        """, unsafe_allow_html=True)
            else:
                st.success("🎉 No vulnerabilities found!", icon="✅")
            
            # Report generation
            st.subheader("📥 Download Full Reports", divider="blue")
            reports = scanner.generate_reports()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # PDF Report
            if reports["pdf"]:
                st.download_button(
                    label="📄 Download PDF Report",
                    data=reports["pdf"],
                    file_name=f"cyber_report_{timestamp}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            else:
                st.error("Failed to generate PDF report. Check logs for details.")
                st.text_area("Logs", scanner.get_logs(), height=200)
            
            # JSON Report
            if reports["json"]:
                st.download_button(
                    label="📊 Download JSON Report",
                    data=reports["json"],
                    file_name=f"cyber_report_{timestamp}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            # HTML Report
            if reports["html"]:
                st.download_button(
                    label="🌐 Download HTML Report",
                    data=reports["html"],
                    file_name=f"cyber_report_{timestamp}.html",
                    mime="text/html",
                    use_container_width=True
                )


if __name__ == "__main__":
    main()
