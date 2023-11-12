import sys
from subprocess import call

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

    match choice.upper():
        case "A":
            print("Running available-ports.py...")
            call(['python', 'portscanner.py'])
        case "B":
            print("2")
            login()
        case "Q":
            print("Q")
            sys.exit()
        case _:
            print("ERROR")
            menu()

def register():
    print("Register function")

def login():
    print("Login function")

# The program is initiated here
main()

