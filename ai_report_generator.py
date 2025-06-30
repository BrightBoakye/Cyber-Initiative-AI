# ai_report_generator.py
from openai import OpenAI

client = OpenAI()  # make sure OPENAI_API_KEY is set in your environment

def generate_ai_summary(vuln_data):
    """
    vuln_data: text string describing detected vulnerabilities
    Returns: AI-generated text summary
    """
    prompt = f"""
    You are a cybersecurity assistant.
    Here is the vulnerability data: {vuln_data}
    Generate a professional, human-readable summary with business risk and remediation advice.
    """
    
    response = client.chat.completions.create(
        model="gpt-4o",  # or "gpt-4.1"
        messages=[
            {"role": "system", "content": "You are a helpful cybersecurity assistant."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )
    return response.choices[0].message.content

