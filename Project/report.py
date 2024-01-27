# Exemplo de geração de relatório PDF com reportlab
from reportlab.pdfgen import canvas

def generate_pdf(report_data, file_path):
    c = canvas.Canvas(file_path)
    for line in report_data:
        c.drawString(100, 100, line)  # Adapte conforme necessário
        c.showPage()
    c.save()

# Exemplo de geração de lista CSV
import csv

def generate_csv(data, file_path):
    with open(file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for row in data:
            csv_writer.writerow(row)
