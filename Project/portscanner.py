import sys
from threading import Thread
import socket
from datetime import datetime
import pickle
from reportlab.pdfgen import canvas
import csv

# File path for pickle file
pickle_file =  open('port_description.dat', 'rb')

# Data and skill information
data = skill = pickle.load(pickle_file)

# Global lists for PDF report and CSV list
report_data = []
csv_data = []

def generate_pdf(report_data, file_path):
    """
    Generate a PDF report containing the provided data.

    :param report_data: The data to include in the PDF report.
    :type report_data: list[str]
    :param file_path: The file path where the PDF report will be saved.
    :type file_path: str
    """
    c = canvas.Canvas(file_path)
    y = 800
    for line in report_data:
        c.drawString(30, y, line)
        y -=20
    c.save()

def generate_csv(data, file_path):
    """
    Generate a CSV file containing the provided data.

    :param data: The data to include in the CSV file.
    :type data: list[list[Any]]
    :param file_path: The file path where the CSV file will be saved.
    :type file_path: str
    """
    with open(file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for row in data:
            csv_writer.writerow(row)

def get_port_description(port):
    """
    Retrieve the description of a port.

    :param port: The port number.
    :type port: int
    :return: The description of the port.
    :rtype: str
    """
    try:
        service_name = socket.getservbyport(port)
        return f"Service: {service_name}"
    except OSError:
        return f"No Known service for port {port}"

def scantcp(r1, r2):
    """
    Scan TCP ports within the specified range.

    :param r1: The starting port number.
    :type r1: int
    :param r2: The ending port number.
    :type r2: int
    """
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

                # Add to PDF report
                report_data.append(f"Port Open: {port} - {description}")

                # Add to CSV list
                csv_data.append([port, description])

                sock.close()
    except Exception as e:
        print(e)

# banner
print('*' * 60)
print(' \tPort scanner \n ')

d = input('\tD - Domain Name | I - IP Address\t')
if d == 'D' or d == 'd':
    rmserver =  input('\t Enter the Domain Name to scan:\t')
    rmip = socket.gethostbyname(rmserver)
elif d == 'I' or d == 'i':
    rmip =  input('\t Enter the IP Address to scan: ')
else:
    print('Wrong input')

port_start1 =  int(input('\t Enter the start port number\t'))
port_last1 =  int(input('\t Enter the last port number\t'))

if port_last1 > 65535:
    print('Range not Ok')
    port_last1 = 65535
    print('Setting last port 65535')

conect =  input('Low connectivity = L | High connectivity = H \t')

if conect == 'L' or conect == 'l':
    c = 1.5
elif conect == 'H' or conect == 'h':
    c = 0.5
else:
    print('\twrong Input')

# Start port scanning in threads
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

# Wait for all threads to complete
for thread in threads:
    thread.join()

print('Exiting Main Thread')
t2 = datetime.now()
total = t2 - t1
print('Scanning complete in ', total)

# Generate report and list
generate_pdf(report_data, "relatorio.pdf")
generate_csv(csv_data, "lista.csv")
