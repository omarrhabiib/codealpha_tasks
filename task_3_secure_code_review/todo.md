# Secure Code Review Checklist

- [x] Create sample vulnerable Python code.
- [x] Perform static code analysis on the sample code.
  - [x] Identify Hardcoded Secret.
  - [x] Identify SQL Injection vulnerability.
  - [x] Identify Command Injection vulnerability.
  - [x] Identify Insecure Deserialization vulnerability.
  - [x] Identify Use of `eval`.
  - [x] Identify Weak Password Hashing.
  - [x] Identify Cross-Site Scripting (XSS) vulnerability.
  - [x] Identify Debug Mode enabled in production-like code.
  - [x] Identify Binding to all interfaces (0.0.0.0).
- [x] Document findings with details (Description, Risk, Snippet, Recommendation).
- [x] Validate findings and recommendations.
- [x] Compile the final report.
- [x] Send the report to the user.

