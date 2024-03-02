from gelfclient import UdpClient
from faker import Faker

fake = Faker()

graylog_server_ip = '0.0.0.0'
graylog_port = 12201  # Update with your Graylog GELF UDP input port

gelf_server = f'{graylog_server_ip}:{graylog_port}'
client = UdpClient(graylog_server_ip, graylog_port, mtu=8000)

# Simulate logs with different IP addresses
for _ in range(10):
    ip_address = fake.ipv4()
    log_message = fake.text()
    log_entry = log_message

    # Send log_entry to Graylog
    client.log("example_logger", log_entry)
