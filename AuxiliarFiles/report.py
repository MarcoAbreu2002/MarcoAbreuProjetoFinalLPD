# Exemplo de geração de relatório PDF com reportlab
from reportlab.pdfgen import canvas

def generate_pdf(report_data, file_path):
    """
    Generate a PDF report using ReportLab.

    Parameters:
    - report_data (list): List of strings representing lines in the report.
    - file_path (str): Path to save the generated PDF file.
    """
    c = canvas.Canvas(file_path)
    for line in report_data:
        c.drawString(100, 100, line)  # Adapte conforme necessário
    c.save()

# Exemplo de geração de lista CSV
import csv

def generate_csv(data, file_path):
    """
    Generate a CSV file.

    Parameters:
    - data (list of lists): List of rows to be written into the CSV file.
    - file_path (str): Path to save the generated CSV file.
    """
    with open(file_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for row in data:
            csv_writer.writerow(row)
