import sys
import subprocess

def main():
    menu()

def menu():
    print("************Aplicação de Segurança Informática**************")
    print()

    choice = input("""
               A: Portos de Rede Disponíveis
               B: UDP flood (DoS)
               Q: SYN flood (TCP SYN)

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
            case "Q":
                print("Q")
                sys.exit()
            case _:
                print("ERROR")
                menu()
    except KeyboardInterrupt:
        print("\nUser interrupted. Stopping the main program.")

if __name__ == "__main__":
    # The program is initiated here
    main()
