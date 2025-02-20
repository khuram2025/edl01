import os
import django
import sys
import logging

# Set up logging
logging.basicConfig(
    filename='/tmp/device_checker.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ch_syslog.settings')
django.setup()

from logs.models import Device

def is_device_approved(ip_address):
    """
    Check if a device with the given IP address is approved to send logs
    """
    logging.debug(f"Checking approval for IP: {ip_address}")
    
    try:
        device = Device.objects.get(ip_address=ip_address)
        logging.debug(f"Found existing device: {device.hostname} ({device.ip_address}), approved: {device.is_approved}")
        return device.is_approved
    except Device.DoesNotExist:
        logging.debug(f"Device not found, creating new device for IP: {ip_address}")
        try:
            # Automatically create the device as unapproved
            Device.objects.create(
                ip_address=ip_address,
                hostname='',
                is_approved=False
            )
            logging.debug(f"Created new device for IP: {ip_address}")
            return False
        except Exception as e:
            logging.error(f"Error creating device: {str(e)}")
            return False

if __name__ == '__main__':
    if len(sys.argv) != 2:
        logging.error("Invalid number of arguments")
        print("Usage: python device_checker.py <ip_address>")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    logging.debug(f"Script called with IP: {ip_address}")
    result = is_device_approved(ip_address)
    logging.debug(f"Result for {ip_address}: {result}")
    # Print 'true' or 'false' for Logstash to parse
    print(str(result).lower()) 