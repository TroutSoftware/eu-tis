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

# WAN Network (For Kali & Attacker) #

resource "incus_network" "wan" {
  name = "incus-wan"
  type = "bridge"

  config = {
    "ipv4.dhcp" = "true"
    "ipv4.address" = "198.18.100.1/24"
    "ipv4.nat"     = "true"
    "ipv6.nat" = "true"
  }
}

# LAN Network (For DVWA & Target & Windows) #

resource "incus_network" "lan" {
  name = "incus-lan"
  type = "bridge"

  config = {
    "ipv4.dhcp" = "false"
    "ipv4.address" = "198.18.200.1/24"
    "ipv4.nat"     = "true"
    "ipv6.address" = "none"
  }
}

### INSTANCES ###

# Router/Firewall #

resource "incus_instance" "router" {
  name    = "Router-Firewall"
  image   = "images:debian/13/cloud"
  running = true

config = {
  "user.user-data" = <<EOF
  #cloud-config
  packages:
    - ifupdown
    - dnsmasq
    - ufw

  write_files:
    - path: /etc/dnsmasq.conf
      content: |
        interface=eth1
        bind-interfaces
        dhcp-broadcast
        dhcp-range=198.18.200.50,198.18.200.100,12h
        domain-needed
        bogus-priv
        no-resolv
        log-queries
        log-dhcp
        server=8.8.8.8
        server=8.8.4.4

    - path: /etc/network/interfaces
      content: |
        auto eth1
        iface eth1 inet static
        address 198.18.200.10
        netmask 255.255.255.0
        gateway 198.18.200.1
      
    - path: /etc/sysctl.conf
      content: |
        net.ipv4.ip_forward=0

  runcmd:
    - ip link set eth1 up
    - sleep 5  # Give eth1 time to initialize
    - systemctl restart networking
    - systemctl restart dnsmasq
    
    - iptables -A FORWARD -i eth1 -o eth0 -j DROP  
    - iptables -A FORWARD -i eth0 -o eth1 -j DROP
    
    - iptables -A FORWARD -i eth1 -o eth1 -j ACCEPT  
    - iptables -A FORWARD -i eth0 -o eth0 -j ACCEPT  
  
    - iptables -A INPUT -p udp --dport 67 -j ACCEPT  
    - iptables -A INPUT -p udp --dport 68 -j ACCEPT  
    - iptables -A INPUT -p udp --dport 53 -j ACCEPT  
    - iptables -A INPUT -p tcp --dport 53 -j ACCEPT  

    - iptables-save > /etc/iptables.rules
    - echo '#!/bin/sh' > /etc/network/if-pre-up.d/iptables
    - echo 'iptables-restore < /etc/iptables.rules' >> /etc/network/if-pre-up.d/iptables
    - chmod +x /etc/network/if-pre-up.d/iptables

  EOF
}

  device {
    name      = "eth0"
    type      = "nic"
    properties = {
      "parent"  = incus_network.wan.name
      "nictype" = "bridged"
    }
  }

  device {
    name      = "eth1"
    type      = "nic"
    properties = {
      "parent"  = incus_network.lan.name
      "nictype" = "bridged"
    }
  }
}


## WAN Instances (Kali) ##

# Attacker-Kali #

resource "incus_instance" "kali" {
  name   = "Attacker"
  image  = "images:kali/cloud"
  running = true

 config = {
    "user.user-data" = <<EOF
    #cloud-config
    package_update: true
    package_upgrade: true
    packages:
      - kali-linux-default
  EOF
  }

  device {
    name      = "eth0"
    type      = "nic"
    properties = {
      "nictype" = "bridged"
      "parent"  = incus_network.wan.name
    }
  }
}


## LAN Instances (Windows, DVWA & Target) ##

# WINDOWS # (bug that i need to fix but it's working)

resource "incus_instance" "windows" {
  name   = "Windows"
  type   = "virtual-machine"
  running = true

  source_instance = {
    project  = "default"
    name     = "windows-template"
    snapshot = "winclient-template"
  }

  device {
    name      = "eth0"
    type      = "nic"
    properties = {
      "nictype" = "bridged"
      "parent"  = incus_network.lan.name
    }
  }
}

resource "incus_instance" "dvwa" {
  name   = "DVWA"
  image  = "images:debian/13/cloud"
  running = true

  config = {
    "user.user-data" = <<EOF
    #cloud-config
    package_update: true
    package_upgrade: true
    packages:
      - apache2
      - mariadb-server
      - mariadb-client
      - php
      - php-mysqli
      - php-gd
      - php-xml
      - php-curl
      - unzip
      - wget
      - php-mysql 
      - php8.4-mysql
      - ufw

    bootcmd:
      - rm -f /etc/resolv.conf
      - echo "nameserver 198.18.200.1" > /etc/resolv.conf

    runcmd:
      # Activer et démarrer les services nécessaires
      - systemctl enable apache2
      - systemctl start apache2
      - systemctl enable mariadb
      - systemctl start mariadb

      # Configurer MySQL/MariaDB
      - mysql -e "CREATE DATABASE dvwa;"
      - mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';"
      - mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
      - mysql -e "FLUSH PRIVILEGES;"

      # Télécharger et installer DVWA depuis le repo officiel
      - wget https://github.com/digininja/DVWA/archive/refs/heads/master.zip -O /tmp/dvwa.zip
      - unzip /tmp/dvwa.zip -d /var/www/html/
      - mv /var/www/html/DVWA-master /var/www/html/dvwa

      # Changer les permissions pour Apache
      - chown -R www-data:www-data /var/www/html/dvwa
      - chmod -R 755 /var/www/html/dvwa


      # Activer mod_rewrite pour Apache (nécessaire pour DVWA)
      - a2enmod rewrite
      - systemctl restart apache2

      # Configurer PHP (pour activer les vulnérabilités nécessaires)
      - sed -i "s/allow_url_include = Off/allow_url_include = On/" /etc/php/8.4/apache2/php.ini
      - sed -i "s/allow_url_fopen = Off/allow_url_fopen = On/" /etc/php/8.4/apache2/php.ini
      - sed -i "s/display_errors = Off/display_errors = On/" /etc/php/8.4/apache2/php.ini
      - sed -i "s/display_startup_errors = Off/display_startup_errors = On/" /etc/php/8.4/apache2/php.ini

      # Activer firewall et autoriser Apache
      - ufw allow 80/tcp
      - ufw allow 443/tcp
      - ufw enable

      # Ajouter une règle iptables pour assurer l’accès externe
      - iptables -A INPUT -p tcp --dport 80 -j ACCEPT
      - iptables -A INPUT -p tcp --dport 443 -j ACCEPT
      - iptables-save > /etc/iptables.rules

      - cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php

      # Redémarrer Apache et MariaDB après configuration
      - systemctl restart apache2
      - systemctl restart mariadb
    EOF
  }

  device {
    name      = "eth0"
    type      = "nic"
    properties = {
      "nictype" = "bridged"
      "parent"  = incus_network.lan.name
    }
  }
}

# TARGET #

resource "incus_instance" "target" {
  name   = "Target"
  image  = "images:debian/13/cloud"
  running = true

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

  device {
    name      = "eth0"
    type      = "nic"
    properties = {
      "nictype" = "bridged"
      "parent"  = incus_network.lan.name
    }
  }
}


# VULNHUB #

resource "incus_instance" "vulhub" {
  name   = "Vulhub"
  image  = "images:ubuntu/22.04/cloud"
  running = true

  config = {
    "user.user-data" = <<EOF
    #cloud-config
    package_update: true
    package_upgrade: true
    packages:
      - docker.io
      - git

    runcmd:
      - systemctl enable docker
      - systemctl start docker
      - git clone https://github.com/vulhub/vulhub.git /opt/vulhub
      - cd /opt/vulhub/thinkphp/5.0.23-rce && docker compose up -d
EOF
  }

  device {
    name      = "eth0"
    type      = "nic"
    properties = {
      "nictype" = "bridged"
      "parent"  = incus_network.lan.name
    }
  }
}
