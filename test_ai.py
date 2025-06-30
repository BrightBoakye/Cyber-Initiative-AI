# test_ai.py
from ai_report_generator import generate_ai_summary

if __name__ == "__main__":
    sample_data = "SQL Injection detected on login page; XSS found in comments section"
    summary = generate_ai_summary(sample_data)
    print("=== AI Summary ===")
    print(summary)
