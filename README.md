# project1

# Web Application Vulnerability Scanner

## Introduction

Web applications are frequent targets of security weaknesses such as Cross-Site Scripting (XSS), SQL Injection (SQLi), and Cross-Site Request Forgery (CSRF). This project presents a Python-based scanner that detects these vulnerabilities by automatically crawling web pages, injecting crafted payloads, analyzing responses, and reporting findings via a Flask-based user interface.



## Abstract

The scanner leverages Python libraries `requests` and `BeautifulSoup` to discover forms and input fields on web pages. Crafted payloads modeled after OWASP Top 10 vulnerability examples are injected into these inputs to test for security flaws. Responses are analyzed using regex and pattern matching techniques to identify vulnerabilities with evidence. The Flask UI facilitates scanning management, detailed report viewing, and exporting results in HTML or CSV formats. This integrated tool supports early identification and remediation of common web app vulnerabilities.



## Tools Used

- Python 3.x  
- requests — HTTP client for interacting with target web pages  
- Flask — Web application framework  
- tabulate — Formatted terminal output  
- OWASP Top 10 checklist — Reference for payloads and testing focus  



## Steps Involved in Building the Project

1. Prepare Python environment and install required libraries.  
2. Crawl target web applications to extract all forms and input fields.  
3. Define payloads simulating XSS, SQLi, and CSRF attacks based on OWASP Top 10.  
4. Inject payloads into each discovered input using appropriate HTTP methods.  
5. Analyze response bodies for evidence of vulnerabilities using regex matching.  
6. Log each vulnerability detected with type, affected URL and parameter, payload, severity, and evidence.  
7. Develop a Flask web interface to control scans, visualize results, and provide report export options.  
8. Implement command-line terminal reporting with formatted output for quick summaries.  

# Installation & Setup

1. Clone this repository:

bash
git clone https://github.com/yourusername/webapp-vuln-scanner.git
cd webapp-vuln-scanner

2.(Optional) Create and activate a virtual environment:

bash
python -m venv venv
source venv/bin/activate  

3.Install dependencies:

bash
pip install Flask Flask-Login

# Usage

1.Run the Flask app to start the web UI:

bash
python app.py

2.Open your browser and go to:

text
http://localhost:5000/login

3.Login with default credentials:

text
Username: admin
Password: password123

4.Enter a target URL to start scanning.

5.View scan results and download reports as CSV or HTML.

6.Print reports in your terminal with the /terminal-report endpoint (after login).

# Contributing

Feel free to fork this repository and contribute features, bug fixes, or improvements!

#License

This project is licensed under the MIT License.

## Conclusion

This project delivers a practical and extensible Python-based web vulnerability scanner integrating automated crawling, payload injection, response analysis, and detailed reporting. The user-friendly Flask UI enhances accessibility and management of scan results. This tool helps security professionals detect and address prevalent web application vulnerabilities efficiently. Future expansion can improve coverage, add asynchronous features, and implement persistent data storage.


