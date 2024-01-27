import sys
import subprocess
import os

def main():
    clear_screen()
    while True:
        menu()

def clear_screen():
    # Clear screen based on the operating system
    if sys.platform.startswith('win'):
        os.system('cls')  # For Windows
    else:
        os.system('clear')  # For Linux and macOS


def menu():
    print("************Aplicação de Segurança Informática**************")
    print()

    choice = input("""
               A: Portos de Rede Disponíveis
               B: UDP flood (DoS)
               C: SYN flood (TCP SYN)
               D: Encrypted Chat
               Q: Quit

               Escolha a opção desejada: """)

    try:
        match choice.upper():
            case "A":
                print("Running available-ports.py...")
                port_scanner_process = subprocess.Popen(['python', 'portscanner.py'])
                port_scanner_process.wait()
            case "B":
                print("Running udp_flood.py...")
                udp_flood_process = subprocess.Popen(['python', 'udpflood.py'])
                udp_flood_process.wait()
            case "C":
                print("Running synflood.py...")
                syn_flood_process = subprocess.Popen(['python', 'synflood.py'])
                syn_flood_process.wait()
            case "D":
                encrypted_chat_menu()
            case "Q":
                print("Exiting the program.")
                sys.exit()
            case _:
                print("ERROR: Invalid choice.")
    except KeyboardInterrupt:
        print("\nUser interrupted. Returning to the menu.")

def encrypted_chat_menu():
    while True:
        print("""
               1: Start Server
               2: Start Client
               3: Read Log Messages
               Q: Back to main menu
        """)

        choice = input("Escolha a opção desejada: ")

        try:
            match choice.upper():
                case "1":
                    start_server()
                case "2":
                    start_client()
                case "3":
                    read_log_messages()
                case "Q":
                    print("Returning to the main menu.")
                    clear_screen()
                    return  # Exit the loop and return to the main menu
                case _:
                    print("ERROR: Invalid choice.")
        except KeyboardInterrupt:
            print("\nUser interrupted. Returning to the menu.")

def start_server():
    # Check if the server is already running
    server_check_process = subprocess.run(['pgrep', '-f', 'server1.py'], capture_output=True, text=True)
    if server_check_process.stdout.strip():
        print("ERROR: Server is already running.")
    else:
        print("Starting the server...")
        # Use -- to terminate options and execute the command
        subprocess.Popen(['gnome-terminal', '--',  'python',  'server1.py'])

def start_client():
    print("Starting the client...")
    subprocess.Popen(['gnome-terminal', '--', 'python', 'client1.py'])

def read_log_messages():
    print("Starting Log Messages...")
    subprocess.Popen(['gnome-terminal', '--', 'python', 'get_log_messages.py'])


if __name__ == "__main__":
    # The program is initiated here
    main()
