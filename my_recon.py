import re

# Define vulnerable parameter groups
class VulnParamGroup:
    def __init__(self, title, parameter_names, high_risk_parameters):
        self.title = title
        self.parameter_names = parameter_names
        self.high_risk_parameters = high_risk_parameters

# Vulnerable parameter groups (with high-risk parameters)
vuln_groups = {
    "ssrf": VulnParamGroup("SSRF", 
                           ["dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir"], 
                           ["url", "redirect", "host", "uri", "callback", "domain"]),
    "sql": VulnParamGroup("SQL", 
                          ["id", "page", "report", "dir", "search", "category", "file", "class", "url", "news", "item", "menu", "lang", "name", "ref", "title", "view", "topic", "thread", "type", "date", "form", "main", "nav", "region"], 
                          ["id", "category", "search", "file", "dir", "url"]),
    "xss": VulnParamGroup("XSS", 
                          ["q", "s", "search", "id", "lang", "keyword", "query", "page", "keywords", "year", "view", "email", "type", "name", "p", "month", "image", "list_type", "url", "terms", "categoryid", "key", "l", "begindate", "enddate"], 
                          ["q", "search", "keyword", "id", "page", "url"]),
    "lfi": VulnParamGroup("LFI", 
                          ["cat", "dir", "action", "board", "date", "detail", "file", "download", "path", "folder", "prefix", "include", "page", "inc", "locate", "show", "doc", "site", "type", "view", "content", "document", "layout", "mod", "conf"], 
                          ["file", "dir", "path", "page", "include", "download"]),
    "or": VulnParamGroup("Open Redirect", 
                         ["next", "url", "target", "rurl", "dest", "destination", "redir", "redirect_uri", "redirect_url", "redirect", "out", "view", "to", "image_url", "go", "return", "returnTo", "return_to", "checkout_url", "continue", "return_path"], 
                         ["redirect", "url", "return", "next"]),
    "rce": VulnParamGroup("RCE", 
                          ["cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func", "arg", "option", "load", "process", "step", "read", "feature", "exe", "module", "payload", "run", "print"], 
                          ["cmd", "exec", "command", "execute", "ping"]),
    "idor": VulnParamGroup("IDOR", 
                           ["id", "userid", "user_id", "account", "profile", "order", "uid", "customer", "resource", "file", "doc", "entity", "session", "record"], 
                           ["id", "userid", "user_id", "order", "profile", "account"])
}

# Function to search for vulnerable parameters
def search_parameters(urls, param_group):
    found_urls = []
    found_details = []  # To hold URL and parameter information for console output
    for url in urls:
        for param in param_group.parameter_names:
            if re.search(f"[?&]{param}=", url):  # Simple regex to find vulnerable parameter in URL
                found_urls.append(url)
                found_details.append(f"URL: {url} | Vulnerable Parameter: {param}")
                break
    return found_urls, found_details

# Function to search for high-risk parameters
def search_high_risk_parameters(urls, param_group):
    high_risk_urls = []
    high_risk_details = []  # To hold URL and high-risk parameter information
    for url in urls:
        for param in param_group.high_risk_parameters:
            if re.search(f"[?&]{param}=", url):  # Regex to find high-risk parameters
                high_risk_urls.append(url)
                high_risk_details.append(f"URL: {url} | High-Risk Parameter: {param}")
                break
    return high_risk_urls, high_risk_details

# Main tool function
def main():
    # Input the .txt file containing URLs
    file_path = input("Enter the path to your .txt file containing URLs: ").strip()
    
    # Read URLs from the file
    try:
        with open(file_path, 'r') as f:
            urls = f.read().splitlines()
    except FileNotFoundError:
        print("File not found. Please enter a valid file path.")
        return
    
    # Ask for the type of vulnerability to check
    print("\nAvailable parameter types to search for:")
    print(", ".join(vuln_groups.keys()))
    param_type = input("\nEnter the parameter type you want to search for (e.g., 'lfi', 'xss', 'sql'): ").strip().lower()
    
    if param_type not in vuln_groups:
        print("Invalid parameter type. Please choose a valid option from the list.")
        return
    
    # Search for vulnerable parameters in URLs
    param_group = vuln_groups[param_type]
    found_urls, found_details = search_parameters(urls, param_group)
    
    # Output the results (Console Output)
    if found_details:
        print(f"\n[+] Found {param_group.title} parameters in the following URLs and parameters:")
        for detail in found_details:
            print(detail)  # Show both URL and vulnerable parameter
    else:
        print(f"\n[-] No {param_group.title} parameters found in the provided URLs.")
    
    # Ask if the user wants to save the output
    if found_urls:
        save_option = input("\nWould you like to save the URLs to a file? (y/n): ").strip().lower()
        if save_option == 'y':
            output_file = input("Enter the output file name (e.g., 'results.txt'): ").strip()
            try:
                with open(output_file, 'w') as f:
                    f.write(f"Found {param_group.title} parameters in the following URLs:\n")
                    for url in found_urls:
                        f.write(url + "\n")  # Save only the URLs
                print(f"\n[+] URLs saved to {output_file}.")
            except Exception as e:
                print(f"[-] An error occurred while saving the file: {e}")
        else:
            print("\n[+] URLs were not saved.")
    
    # Ask if the user wants to see high-risk parameters
    show_high_risk = input("\nWould you like to see the high-risk parameters? (y/n): ").strip().lower()
    if show_high_risk == 'y':
        high_risk_urls, high_risk_details = search_high_risk_parameters(found_urls, param_group)
        
        if high_risk_details:
            print(f"\n[+] High-risk {param_group.title} parameters in the following URLs:")
            for detail in high_risk_details:
                print(f"\033[1;31m{detail}\033[0m")  # Highlight high-risk parameters in red
            
            # Ask if the user wants to save the high-risk parameters
            save_high_risk = input("\nWould you like to save the high-risk URLs and parameters to a file? (y/n): ").strip().lower()
            if save_high_risk == 'y':
                high_risk_file = input("Enter the high-risk output file name (e.g., 'high_risk_results.txt'): ").strip()
                try:
                    with open(high_risk_file, 'w') as f:
                        f.write(f"High-risk {param_group.title} parameters found in the following URLs:\n")
                        for detail in high_risk_details:
                            f.write(detail + "\n")  # Save high-risk URLs and parameters
                    print(f"\n[+] High-risk URLs and parameters saved to {high_risk_file}.")
                except Exception as e:
                    print(f"[-] An error occurred while saving the file: {e}")
            else:
                print("\n[+] High-risk URLs and parameters were not saved.")
        else:
            print(f"\n[-] No high-risk {param_group.title} parameters found.")

if __name__ == "__main__":
    main()
