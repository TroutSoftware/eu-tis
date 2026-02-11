terraform {
  required_providers {
    incus = {
      source  = "lxc/incus"
      version = "0.2.0"
    }
  }
}

provider "incus" {}

### NETWORKS ###

# WAN Network (For Attacker) #
resource "incus_network" "wan" {
  name = "incus-wan"
  type = "bridge"

  config = {
    "ipv4.dhcp"    = "true"
    "ipv4.address" = "198.18.100.1/24"
    "ipv4.nat"     = "true"
    "ipv6.nat"     = "true"
  }
}

# LAN Network (For Targets) #
resource "incus_network" "lan" {
  name = "incus-lan"
  type = "bridge"

  config = {
    "ipv4.dhcp"    = "false"
    "ipv4.address" = "198.18.200.1/24"
    "ipv4.nat"     = "true"
    "ipv6.address" = "none"
  }
}



### INSTANCES ###

# Router Container
resource "incus_instance" "router" {
  name             = "Router-Firewall"
  image            = "images:debian/13/cloud"
  running          = true
  wait_for_network = false

  config = {
    "user.network-config" = <<EOF
version: 2
ethernets:
  eth0:
    addresses:
      - 198.18.100.254/24
    routes:
      - to: 0.0.0.0/0
        via: 198.18.100.1
    nameservers:
      addresses: [8.8.8.8, 8.8.4.4]
  eth1:
    addresses:
      - 198.18.200.10/24
EOF
    "user.user-data"      = <<EOF
#cloud-config
packages:
  - ifupdown
  - dnsmasq
  - iptables
  - iptables-persistent
  - softflowd

write_files:
  - path: /etc/dnsmasq.conf
    content: |
      interface=eth1
      bind-interfaces
      dhcp-broadcast
      dhcp-range=198.18.200.50,198.18.200.100,12h
      dhcp-option=3,198.18.200.10
      dhcp-option=6,198.18.200.10
      domain-needed
      bogus-priv
      no-resolv
      log-queries
      log-dhcp
      server=8.8.8.8
      server=8.8.4.4

  - path: /etc/sysctl.conf
    content: |
      net.ipv4.ip_forward=1

  - path: /etc/iptables/rules.v4
    content: |
      *filter
      :INPUT ACCEPT [0:0]
      :FORWARD DROP [0:0]
      :OUTPUT ACCEPT [0:0]

      # Allow established and related connections
      -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

      # Block WAN (198.18.100.0/24) to LAN (198.18.200.0/24)
      -A FORWARD -s 198.18.100.0/24 -d 198.18.200.0/24 -j DROP

      # Block LAN (198.18.200.0/24) to WAN (198.18.100.0/24)
      -A FORWARD -s 198.18.200.0/24 -d 198.18.100.0/24 -j DROP

      # Allow LAN to Internet (not to WAN subnet)
      -A FORWARD -s 198.18.200.0/24 -j ACCEPT

      # Allow WAN to Internet (not to LAN subnet)
      -A FORWARD -s 198.18.100.0/24 -j ACCEPT

      COMMIT

  # Separate softflowd service for eth0 (WAN interface)
  - path: /etc/systemd/system/softflowd-eth0.service
    permissions: "0644"
    content: |
      [Unit]
      Description=softflowd NetFlow exporter for eth0
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      ExecStart=/usr/sbin/softflowd -i eth0 -n 198.18.200.20:2055 -v 9 -t maxlife=60 -d -p /var/run/softflowd-eth0.pid -c /var/run/softflowd-eth0.ctl
      Restart=always
      RestartSec=5

      [Install]
      WantedBy=multi-user.target

  # Separate softflowd service for eth1 (LAN interface)
  - path: /etc/systemd/system/softflowd-eth1.service
    permissions: "0644"
    content: |
      [Unit]
      Description=softflowd NetFlow exporter for eth1
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      ExecStart=/usr/sbin/softflowd -i eth1 -n 198.18.200.20:2055 -v 9 -t maxlife=60 -d -p /var/run/softflowd-eth1.pid -c /var/run/softflowd-eth1.ctl
      Restart=always
      RestartSec=5

      [Install]
      WantedBy=multi-user.target

runcmd:
  - sleep 5
  - sysctl -p
  - systemctl restart dnsmasq
  - iptables-restore < /etc/iptables/rules.v4
  - systemctl enable netfilter-persistent
  - systemctl daemon-reload
  - systemctl enable --now softflowd-eth0
  - systemctl enable --now softflowd-eth1
EOF
  }

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.wan.name
    }
  }

  device {
    name = "eth1"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }
}

# Attacker external (WAN) #
resource "incus_instance" "attacker-external" {
  name    = "Attacker-external"
  image   = "images:debian/13/cloud"
  running = true

  depends_on = [incus_instance.router]

  config = {
    "limits.cpu"     = "4"
    "limits.memory"  = "8GiB"
    "user.user-data" = <<EOF
#cloud-config
packages:
  - iputils-ping
  - tcpdump
  - nmap
  - curl
  - wget

runcmd:
  # Add route to LAN network via Router-Firewall (IP fixe)
  - sleep 5
  - ip route add 198.18.200.0/24 via 198.18.100.254

  # Make route persistent
  - echo "up ip route add 198.18.200.0/24 via 198.18.100.254 2>/dev/null || true" >> /etc/network/interfaces
EOF
  }

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.wan.name
    }
  }
}

# Attacker internal (LAN) #
resource "incus_instance" "attacker-internal" {
  name    = "Attacker-internal"
  image   = "images:debian/13/cloud"
  running = true

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  config = {
    "user.user-data" = <<EOF
#cloud-config
bootcmd:
  - rm -f /etc/resolv.conf
  - echo "nameserver 198.18.200.1" > /etc/resolv.conf

runcmd:
  - dhclient eth0
EOF
  }
}



# DVWA (LAN) #
resource "incus_instance" "dvwa" {
  name    = "DVWA"
  image   = "images:debian/13/cloud"
  type    = "container"
  running = true

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  config = {
    "user.user-data" = <<EOF
#cloud-config
package_update: true
packages:
  - apache2
  - mariadb-server
  - php
  - php-mysqli
  - wget
  - unzip

bootcmd:
  - rm -f /etc/resolv.conf
  - echo "nameserver 198.18.200.1" > /etc/resolv.conf

runcmd:
  # Configuration DVWA
  - systemctl enable apache2 mariadb
  - systemctl start apache2 mariadb
  - mysql -e "CREATE DATABASE dvwa; CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd'; GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';"
  - wget -O /tmp/dvwa.zip https://github.com/digininja/DVWA/archive/refs/heads/master.zip
  - unzip /tmp/dvwa.zip -d /var/www/html/
  - mv /var/www/html/DVWA-master /var/www/html/dvwa
  - chown -R www-data:www-data /var/www/html/dvwa
EOF
  }
}

# Target (LAN) #
resource "incus_instance" "target" {
  name    = "Target"
  image   = "images:ubuntu/22.04/cloud"
  type    = "container"
  running = true

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  config = {
    "user.user-data" = <<EOF
#cloud-config
bootcmd:
  - rm -f /etc/resolv.conf
  - echo "nameserver 198.18.200.1" > /etc/resolv.conf

runcmd:
  - dhclient eth0
EOF
  }
}

# Windows VM (LAN) #
resource "incus_instance" "windows" {
  name             = "Windows"
  type             = "virtual-machine"
  running          = true
  profiles         = ["default"]
  wait_for_network = false

  source_instance = {
    name     = "windows-template"
    project  = "default"
    snapshot = "winclient-template"
  }

  config = {
    "limits.cpu"    = "4"
    "limits.memory" = "6GiB"
    "raw.qemu"      = "-device intel-hda -device hda-duplex -audio spice"
  }

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  device {
    name = "root"
    type = "disk"
    properties = {
      path = "/"
      pool = "incus-storage"
      size = "55GiB"
    }
  }

  device {
    name = "vtpm"
    type = "tpm"
    properties = {
      path = "/dev/tpm0"
    }
  }
}

# NetFlow Collector with Web Dashboard (LAN) #
resource "incus_instance" "netflow_collector" {
  name    = "NetFlow-Collector"
  image   = "images:debian/13/cloud"
  type    = "container"
  running = true

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  # Proxy device to access web dashboard from host
  # Access via http://localhost:8080
  device {
    name = "http-proxy"
    type = "proxy"
    properties = {
      listen  = "tcp:0.0.0.0:8080"
      connect = "tcp:127.0.0.1:80"
    }
  }

  config = {
    "user.network-config" = <<EOF
version: 2
ethernets:
  eth0:
    dhcp4: false
    addresses:
      - 198.18.200.20/24
    routes:
      - to: 0.0.0.0/0
        via: 198.18.200.10
    nameservers:
      addresses: [198.18.200.10]
EOF

    "user.user-data" = <<EOF
#cloud-config
package_update: true
packages:
  - nfdump
  - apache2
  - php
  - php-cli
  - libapache2-mod-php
  - rrdtool
  - librrd-dev
  - librrds-perl
  - libmailtools-perl
  - libsocket6-perl
  - perl
  - git
  - tcpdump
  - net-tools
  - build-essential
  - libperl-dev
  - cpanminus

write_files:
  - path: /etc/systemd/system/nfcapd.service
    permissions: "0644"
    content: |
      [Unit]
      Description=NetFlow/IPFIX collector (nfcapd)
      After=network-online.target
      Wants=network-online.target

      [Service]
      User=www-data
      Group=www-data
      ExecStart=/usr/bin/nfcapd -w /var/cache/nfdump -p 2055 -t 300
      Restart=always
      RestartSec=5

      [Install]
      WantedBy=multi-user.target

  - path: /root/nfsen.conf
    permissions: "0644"
    content: |
      $$BASEDIR = "/var/nfsen";
      $$BINDIR = "/usr/bin";
      $$LIBEXECDIR = "/opt/nfsen/libexec";
      $$CONFDIR = "/opt/nfsen/etc";
      $$HTMLDIR = "/var/www/html/nfsen";
      $$DOCDIR = "/var/www/html/nfsen-doc";
      $$VARDIR = "$$BASEDIR/var";
      $$PROFILESTATDIR = "$$BASEDIR/profiles-stat";
      $$PROFILEDATADIR = "$$BASEDIR/profiles-data";
      $$BACKEND_PLUGINDIR = "$$BASEDIR/plugins";
      $$FRONTEND_PLUGINDIR = "$$HTMLDIR/plugins";
      $$PREFIX = '/usr/bin';
      $$COMMSOCKET = "$$VARDIR/nfsen.comm";
      $$PIDDIR = "$$VARDIR/run";
      $$USER = "www-data";
      $$WWWUSER = "www-data";
      $$WWWGROUP = "www-data";
      $$BUFFLEN = 200000;
      $$ZIPcollected = 1;
      $$ZIPprofiles = 1;
      $$PROFILERS = 1;
      $$DISKLIMIT = 95;
      $$EXTENSIONS = 'all';
      %sources = (
          'lab-router' => {
              'port' => '2055',
              'col' => '#0000ff',
              'type' => 'netflow'
          }
      );
      $$low_water = 90;
      $$syslog_facility = 'local3';
      1;

  - path: /var/www/html/index.html
    permissions: "0644"
    content: |
      <!DOCTYPE html>
      <html>
      <head>
          <meta http-equiv="refresh" content="0; url=/nfsen/nfsen.php">
          <title>NetFlow Collector</title>
      </head>
      <body>
          <h1>NetFlow Collector Dashboard</h1>
          <p>Redirecting to <a href="/nfsen/nfsen.php">NfSen Dashboard</a>...</p>
      </body>
      </html>

  - path: /root/setup-nfsen.sh
    permissions: "0755"
    content: |
      #!/bin/bash
      set -e

      # Install required Perl modules (RRDs is already installed via librrd-dev)
      echo "Installing Perl modules..."
      cpanm --notest Mail::Header || true
      cpanm --notest Socket6 || true
      cpanm --notest Sys::Syslog || true

      # Create nfdump directory
      mkdir -p /var/cache/nfdump
      chown -R www-data:www-data /var/cache/nfdump

      # Clone and install NfSen
      cd /opt
      if [ ! -d "nfsen" ]; then
        git clone https://github.com/p-alik/nfsen.git
      fi
      cd nfsen
      cp /root/nfsen.conf etc/nfsen.conf

      # Run installer non-interactively
      echo "" | ./install.pl etc/nfsen.conf || true

      # Fix permissions
      chown -R www-data:www-data /var/nfsen /var/www/html/nfsen 2>/dev/null || true
      chmod -R 755 /var/www/html/nfsen 2>/dev/null || true

      # Start NfSen
      /var/nfsen/bin/nfsen start 2>/dev/null || true

      echo "NfSen installation complete!"

runcmd:
  - sleep 5
  - systemctl enable apache2
  - systemctl start apache2
  - systemctl daemon-reload
  # Disable and mask the default nfdump service to prevent port conflict
  - systemctl stop nfdump.service || true
  - systemctl disable nfdump.service || true
  - systemctl mask nfdump.service || true
  # Now start the custom nfcapd service
  - systemctl enable --now nfcapd.service
  - sleep 10
  - /root/setup-nfsen.sh 2>&1 | tee /var/log/nfsen-install.log
  - systemctl restart apache2
EOF
  }
}

