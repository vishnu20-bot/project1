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

#  Objectives

Automate the process of identifying vulnerabilities in web applications.

Detect common security issues such as:

XSS (Cross-Site Scripting)

SQL Injection

CSRF (Cross-Site Request Forgery)

Provide an easy-to-use web interface for scanning and viewing reports.

Generate a detailed vulnerability report with severity levels and evidence.

# Features of the Project

## Crawling: Automatically extracts links and form fields from target URLs.

## Payload Injection: Tests input fields using a predefined set of malicious payloads.

## Response Analysis:

Detects reflected payloads for XSS.

Matches error signatures for SQL Injection.

## User Interface:

Start scans via Flask dashboard.

View scan results with details and severity.

## Logging & Reporting:

Stores data in an SQLite database.

Generates exportable HTML reports.

## OWASP Top 10 Mapping:

XSS → OWASP A07:2021

SQL Injection → OWASP A03:2021

CSRF → OWASP A05:2021

 # Steps Involved in Building the Project
 
## Web Crawling

Used requests to fetch target pages.

Parsed HTML with BeautifulSoup to find:

Forms

Links

Input fields

## Vulnerability Testing

### XSS Detection:

Injected payloads like <script>alert(1)</script>.

Checked for payload reflection in HTTP responses.

### SQL Injection Detection:

Sent payloads such as ' OR '1'='1 and "' UNION SELECT NULL--".

Used regex to detect SQL error messages in responses.

### CSRF Analysis:

Checked for missing anti-CSRF tokens in forms.

## Pattern Matching & Heuristic Analysis

### Used regex to identify:

SQL error keywords ("syntax error", "mysql_fetch", "ORA-00933", etc.).

Script tags for XSS detection.

## Flask Web Interface

### Developed UI with:

Home Page: Start new scan by entering target URL.

Scan Results Page: Displays vulnerabilities by type and severity.

Download Report: Generates HTML/PDF report.

## Logging & Reporting

Each vulnerability is logged with:

Vulnerability Type (XSS, SQLi, CSRF)

URL & Parameter

Payload Evidence

Severity Level (Low, Medium, High)

## Deliverables

Python Scripts:

scanner.py – Core scanning engine

app.py – Flask-based UI

Database:

scanner.db – Stores scan logs and results

Reports:

HTML/PDF reports generated from database

# Screenshots:

## Flask Dashboard

## Vulnerability Report Page

# GitHub Repository:

## Source code and documentation

from flask import Flask, render_template_string, request, redirect, url_for, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import csv
from io import StringIO
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Change to a secure secret key

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

### Dummy user (Replace with real user DB in production)
users = {'admin': {'password': 'password123'}}

class User(UserMixin):
    def _init_(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None


### Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username]['password'] == password:
            user = User(username)
            login_user(user)
            return redirect(url_for('report'))
        return 'Invalid credentials', 401
    ### Simple login form
    return '''
        <form method="post">
            Username: <input name="username" type="text" /><br/>
            Password: <input name="password" type="password" /><br/>
            <input type="submit" value="Login" />
        </form>
    '''
### Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

### Sample vulnerability scan data (Replace with real scan results)
scan_results = [
    {'type': 'XSS', 'url': 'http://example.com/search', 'parameter': 'q', 'payload': "<script>alert(1)</script>", 'severity': 'High', 'evidence': 'Reflected script in response'},
    {'type': 'SQLi', 'url': 'http://example.com/login', 'parameter': 'username', 'payload': "' OR '1'='1", 'severity': 'High', 'evidence': 'SQL error in response'},
]

### HTML template for report page
html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Scan Report</title>
    <style>
        table { border-collapse: collapse; width: 100%; }
        th, td { padding: 8px; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .High { color: red; font-weight: bold; }
        .Medium { color: orange; }
        .Low { color: green; }
        pre { white-space: pre-wrap; }
    </style>
</head>
<body>
    <p>Logged in as: {{ current_user.id }} | <a href="{{ url_for('logout') }}">Logout</a></p>
    <h1>Vulnerability Scan Report</h1>
    <p><strong>Scan Date:</strong> {{ scan_date }}</p>
    <table>
        <thead>
            <tr>
                <th>Type</th><th>URL</th><th>Parameter</th><th>Payload</th><th>Severity</th><th>Evidence</th>
            </tr>
        </thead>
        <tbody>
            {% for item in scan_results %}
            <tr>
                <td>{{ item.type }}</td><td>{{ item.url }}</td><td>{{ item.parameter }}</td>
                <td><pre>{{ item.payload }}</pre></td>
                <td class="{{ item.severity }}">{{ item.severity }}</td>
                <td><pre>{{ item.evidence }}</pre></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <form action="{{ url_for('download_report') }}" method="get">
        <label for="format">Download report as:</label>
        <select name="format" id="format">
            <option value="html">HTML</option>
            <option value="csv">CSV</option>
   </select>
        <button type="submit">Download</button>
    </form>
</body>
</html>
"""

### Protected report page
@app.route('/')
@login_required
def report():
    return render_template_string(
        html_template,
        scan_results=scan_results,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        current_user=current_user
    )

### Download report route
@app.route('/download-report')
@login_required
def download_report():
    fmt = request.args.get('format', 'html').lower()
    if fmt == 'csv':
        si = StringIO()
        fieldnames = ['Type', 'URL', 'Parameter', 'Payload', 'Severity', 'Evidence']
        writer = csv.DictWriter(si, fieldnames=fieldnames)
        writer.writeheader()
        for r in scan_results:
            writer.writerow({
 'Type': r['type'],
                'URL': r['url'],
                'Parameter': r['parameter'],
                'Payload': r['payload'],
                'Severity': r['severity'],
                'Evidence': r['evidence'],
            })
        output = si.getvalue()
        resp = make_response(output)
        resp.headers["Content-Disposition"] = "attachment; filename=vulnerability_report.csv"
        resp.headers["Content-Type"] = "text/csv"
        return resp
    else:
        html_content = render_template_string(
            html_template,
            scan_results=scan_results,
            scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            current_user=current_user
        )
        resp = make_response(html_content)
        resp.headers["Content-Disposition"] = "attachment; filename=vulnerability_report.html"
        resp.headers["Content-Type"] = "text/html"
        return resp

if __name__ == '__main__':
    app.run(debug=True)

# Challenges Faced

Handling dynamic content and JavaScript-heavy sites.

Avoiding false positives in vulnerability detection.

Managing timeouts and rate-limiting from servers. 

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

# License

This project is licensed under the MIT License.

# Conclusion

This project delivers a practical and extensible Python-based web vulnerability scanner integrating automated crawling, payload injection, response analysis, and detailed reporting. The user-friendly Flask UI enhances accessibility and management of scan results. This tool helps security professionals detect and address prevalent web application vulnerabilities efficiently. Future expansion can improve coverage, add asynchronous features, and implement persistent data storage.


