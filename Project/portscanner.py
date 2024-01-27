from threading import Thread
import socket
from datetime import datetime
import pickle
from reportlab.pdfgen import canvas
import csv

pickle_file = open('port_description.dat', 'rb')
data = skill = pickle.load(pickle_file)

# Lista global para relatório PDF e lista CSV
report_data = []
csv_data = []

def generate_pdf(report_data, file_path):
    c = canvas.Canvas(file_path)
    for line in report_data:
        c.drawString(100, 100, line)
        c.showPage()
    c.save()

def generate_csv(data, file_path):
    with open(file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for row in data:
            csv_writer.writerow(row)

def get_port_description(port):
    try:
        service_name = socket.getservbyport(port)
        return f"Service: {service_name}"
    except OSError:
        return f"No Known service for port {port}"

def scantcp(r1, r2):
    global report_data, csv_data

    try:
        for port in range(r1, r2):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(c)
            result = sock.connect_ex((rmip, port))
            if result == 0:
                description = data.get(port, 'Not in Database')
                if description == 'Not in Database':
                    description = get_port_description(port)
                print('Port Open:-->\t', port, '--', description)

                # Adicione ao relatório PDF
                report_data.append(f"Port Open: {port} - {description}")

                # Adicione à lista CSV
                csv_data.append([port, description])

                sock.close()
    except Exception as e:
        print(e)

#banner
print('*' * 60)
print(' \tPort scanner \n ')

d = input('\tD - Domain Name | I - IP Address\t')
if d == 'D' or d == 'd':
    rmserver = input('\t Enter the Domain Name to scan:\t')
    rmip = socket.gethostbyname(rmserver)
elif d == 'I' or d == 'i':
    rmip = input('\t Enter the IP Address to scan: ')
else:
    print('Wrong input')

port_start1 = int(input('\t Enter the start port number\t'))
port_last1 = int(input('\t Enter the last port number\t'))

if port_last1 > 65535:
    print('Range not Ok')
    port_last1 = 65535
    print('Setting last port 65535')

conect = input('Low connectivity = L | High connectivity = H \t')

if conect == 'L' or conect == 'l':
    c = 1.5
elif conect == 'H' or conect == 'h':
    c = 0.5
else:
    print('\twrong Input')

# Iniciar a varredura de portas em threads
print("\nScanning in progress... ", rmip)
print('*' * 60)

t1 = datetime.now()
total_ports = port_last1 - port_start1
ports_by_one_thread = 30

total_threads = total_ports // ports_by_one_thread

if total_ports % ports_by_one_thread != 0:
    total_threads += 1

if total_threads > 300:
    ports_by_one_thread = total_ports // 300

    if total_ports % 300 != 0:
        ports_by_one_thread += 1

    total_threads = total_ports // ports_by_one_thread

    if total_ports % total_threads != 0:
        total_threads += 1

threads = []
start1 = port_start1

try:
    for i in range(total_threads):
        last1 = start1 + ports_by_one_thread

        if last1 >= port_last1:
            last1 = port_last1

        port_thread = Thread(target=scantcp, args=(start1, last1))
        port_thread.start()
        threads.append(port_thread)
        start1 = last1

except KeyboardInterrupt:
    print("\nUser interrupted. Stopping the port scan.")

# Aguarde a conclusão de todas as threads
for thread in threads:
    thread.join()

print('Exiting Main Thread')
t2 = datetime.now()
total = t2 - t1
print('Scanning complete in ', total)

# Gerar relatório e lista
generate_pdf(report_data, "relatorio.pdf")
generate_csv(csv_data, "lista.csv")
