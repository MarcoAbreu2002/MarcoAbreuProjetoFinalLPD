import sys
import subprocess

def main():
    while True:
        menu()

def menu():
    print("************Aplicação de Segurança Informática**************")
    print()

    choice = input("""
               A: Portos de Rede Disponíveis
               B: UDP flood (DoS)
               C: SYN flood (TCP SYN)
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
            case "Q":
                print("Exiting the program.")
                sys.exit()
            case _:
                print("ERROR: Invalid choice.")
    except KeyboardInterrupt:
        print("\nUser interrupted. Returning to the menu.")

if __name__ == "__main__":
    # The program is initiated here
    main()
