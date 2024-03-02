import logging
import graypy
import random
import socket
import time

# Configuration for Graylog
GRAYLOG_HOST = '0.0.0.0'
GRAYLOG_PORT = 12201

# Function to generate a random IP address
def generate_random_ip():
    """
    Generates a random IP address in the format xxx.xxx.xxx.xxx.
    """
    return f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'

# Configure logging to send GELF messages to Graylog
logger = logging.getLogger('graylog_logger')
logger.setLevel(logging.DEBUG)
handler = graypy.GELFTCPHandler(GRAYLOG_HOST, GRAYLOG_PORT)
logger.addHandler(handler)

# Generate and log mock messages with different IPs
for _ in range(30):  # You can change the number of logs as needed
    ip_address = generate_random_ip()

    # Log a mock message with the random IP address
    logger.info('Mock log message with IP: %s', ip_address)

    # Sleep for a short duration to simulate time passing between logs
    time.sleep(1)

# Close the logger to ensure all logs are sent
logger.handlers.clear()
