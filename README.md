# my_recon
This **Vulnerability Recon Tool** is designed to help bug bounty hunters and penetration testers quickly identify vulnerable parameters in URLs. It searches for common vulnerabilities like **LFI**, **SQLi**, **XSS**, and more, and highlights high-risk parameters that are most likely to be exploited.

# Vulnerability Reconnaissance Tool

## Introduction
This **Vulnerability Recon Tool** is designed to help bug bounty hunters and penetration testers quickly identify vulnerable parameters in URLs. It searches for common vulnerabilities like **LFI**, **SQLi**, **XSS**, and more, and highlights high-risk parameters that are most likely to be exploited.

The tool is interactive, allowing users to specify the vulnerability they are looking for, scan a list of URLs, and save both the vulnerable and high-risk results to a file.

## Features
- **Find Vulnerable Parameters**: Search for parameters vulnerable to various attacks such as LFI, SQLi, XSS, and more.
- **High-Risk Parameter Highlighting**: Highlights the most likely vulnerable parameters, helping you focus on high-priority issues.
- **Save Results**: Saves both vulnerable URLs and high-risk parameters to output files.
- **Interactive Workflow**: Asks users for input, ensuring an easy-to-use experience.

- STEPS
python3 recon_tool.py
Enter the path to your .txt file containing URLs: urls.txt
Available parameter types to search for: ssrf, sql, xss, lfi, or, rce, idor
Enter the parameter type you want to search for (e.g., 'lfi', 'xss', 'sql'): lfi

[+] Found LFI parameters in the following URLs:
URL: https://example.com?file=path/to/file | Vulnerable Parameter: file

Would you like to save the URLs to a file? (y/n): y
Enter the output file name (e.g., 'results.txt'): lfi_results.txt
[+] URLs saved to lfi_results.txt.

Would you like to see the high-risk parameters? (y/n): y
[+] High-risk LFI parameters in the following URLs:
URL: https://example.com?file=path/to/file | High-Risk Parameter: file

Would you like to save the high-risk URLs and parameters to a file? (y/n): y
Enter the high-risk output file name (e.g., 'high_risk_results.txt'): lfi_high_risk.txt
[+] High-risk URLs and parameters saved to lfi_high_risk.txt.
