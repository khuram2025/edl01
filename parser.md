## Setting Up Django Syslog Receiver as a Persistent Systemd Service on Ubuntu

This guide explains how to configure a Django Syslog Receiver command to run as a persistent systemd service on Ubuntu. The goal is to ensure the service runs continuously, starts on system boot, and handles privileged ports using iptables redirection.

---

### 1. Create the systemd Service File

```bash
sudo nano /etc/systemd/system/syslog_receiver.service
```

Add the following content to the file:

```ini
[Unit]
Description=Django Syslog Receiver Service
After=network.target

[Service]
WorkingDirectory=/home/net/django_project/ch_syslog
Environment="PYTHONPATH=/home/net/django_project/ch_syslog"
Environment="VIRTUAL_ENV=/home/net/django_project/venv"
Environment="PATH=/home/net/django_project/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ExecStart=/home/net/django_project/venv/bin/python3 /home/net/django_project/ch_syslog/manage.py syslog_receiver

Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 2. Redirect Privileged Port 514 to Non-Privileged Port 1514

Syslog services typically require binding to port 514, which is a privileged port (<1024). Running the service as a non-root user will result in a permission error. Use iptables to redirect traffic from port 514 to an unprivileged port like 1514.

```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 1514
```

### 3. Make iptables Rules Persistent

Install iptables-persistent to ensure port redirection rules are saved across reboots:

```bash
sudo apt install iptables-persistent
```

During installation, it will ask to save current IPv4 and IPv6 rules. Choose 'Yes'.

To manually save rules after adding new ones:

```bash
sudo netfilter-persistent save
```

Check the rules:

```bash
sudo iptables -t nat -L -n -v
```

### 4. Set Correct Permissions

Ensure your user (e.g., `net`) has proper permissions on the project directory:

```bash
sudo chown -R net:net /home/net/django_project/
sudo chmod -R 755 /home/net/django_project/
```

### 5. Enable and Start the Service

Reload systemd to apply changes:

```bash
sudo systemctl daemon-reload
```

Enable the service to start on boot:

```bash
sudo systemctl enable syslog_receiver.service
```

Start the service:

```bash
sudo systemctl start syslog_receiver.service
```

### 6. Check Service Status and Logs

Check the status of the service:

```bash
sudo systemctl status syslog_receiver.service
```

View service logs in real-time:

```bash
sudo journalctl -u syslog_receiver.service -f
```

### 7. Verify Redirection is Working

Ensure the iptables rule is in place after reboot:

```bash
sudo iptables -t nat -L -n -v
```

Expected output should contain a line like this:

```
REDIRECT udp -- anywhere anywhere udp dpt:514 to:1514
```

### Summary
- The service runs as a non-root user (e.g., `net`)
- Port 514 is redirected to 1514 using iptables
- iptables rules are made persistent with `iptables-persistent`
- The service is configured to restart automatically on failures and reboots

This setup allows the Django Syslog Receiver to receive syslog messages on port 514 without running as root.

