from django import template
from datetime import datetime
import re

register = template.Library()

# Protocol number to name mapping
PROTOCOL_NAMES = {
    '1': 'ICMP',
    '6': 'TCP',
    '17': 'UDP',
    '50': 'ESP',
    '47': 'GRE',
    # Add more protocols as needed
}

@register.filter
def split(value, separator=','):
    """Split a string into a list using the given separator."""
    return value.split(separator)

@register.filter
def format_eventtime(log):
    try:
        # Extract date and time from the message field using regex
        message = log.get('message', '')
        date_match = re.search(r'date=(\d{4}-\d{2}-\d{2})', message)
        time_match = re.search(r'time=(\d{2}:\d{2}:\d{2})', message)
        
        if date_match and time_match:
            date = date_match.group(1)
            time = time_match.group(1)
            return f"{date} {time}"
        return "Unknown"  # Return Unknown if we can't extract from message
            
    except (ValueError, KeyError, TypeError, AttributeError):
        return "Unknown"

@register.filter
def format_datetime(timestamp):
    """Format ISO timestamp to readable datetime."""
    try:
        if not timestamp:
            return ''
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError):
        return timestamp or ''

@register.filter
def protocol_name(proto_number):
    """Convert protocol number to protocol name."""
    if not proto_number:
        return ''
    # Convert to string in case it's passed as integer
    proto_str = str(proto_number)
    return PROTOCOL_NAMES.get(proto_str, proto_str)

@register.filter
def get_range(value, arg=1):
    """Generate a range of numbers from 1 to value."""
    try:
        value = int(value)
        return range(1, value + 1)
    except (ValueError, TypeError):
        return range(0)

@register.filter
def percentage_of(value, max_value):
    """Calculate percentage of value against max_value"""
    try:
        value = float(value)
        max_value = float(max_value)
        if max_value > 0:
            return min(100, (value / max_value) * 100)
        return 0
    except (ValueError, TypeError):
        return 0
