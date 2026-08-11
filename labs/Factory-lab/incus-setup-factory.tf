terraform {
  required_providers {
    incus = {
      source  = "lxc/incus"
      version = "0.2.0"
    }
  }
}

provider "incus" {}

### PROJECT AND STORAGE ###

variable "incus_project_name" {
  description = "Dedicated Incus project for the factory lab"
  type        = string
  default     = "Factory-lab"
}

resource "incus_project" "factory" {
  name        = var.incus_project_name
  description = "Simulated factory IT and OT infrastructure"

  config = {
    "features.images"          = "true"
    "features.networks"        = "false"
    "features.networks.zones"  = "false"
    "features.profiles"        = "true"
    "features.storage.buckets" = "true"
    "features.storage.volumes" = "true"
  }
}

# Copy the base image into the isolated project as an OpenTofu-managed
# resource. This ensures tofu destroy removes the image before the project.
resource "incus_image" "factory_debian" {
  project = incus_project.factory.name
  aliases = ["factory-debian-13"]

  source_image = {
    remote       = "images"
    name         = "debian/13/cloud"
    copy_aliases = false
  }
}

# Storage pools are server-wide Incus objects. This dedicated pool is used only
# by the Factory-lab profile and its project-scoped instance volumes.
resource "incus_storage_pool" "factory" {
  name        = "incus-storage-factory"
  driver      = "dir"
  description = "Dedicated storage pool for the factory lab"
  project     = "default"
}

resource "incus_profile" "factory_base" {
  name        = "factory-base"
  project     = incus_project.factory.name
  description = "Base storage profile for factory lab instances"

  device {
    name = "root"
    type = "disk"
    properties = {
      path = "/"
      pool = incus_storage_pool.factory.name
    }
  }
}

### NETWORKS ###

# WAN Network (For Attacker) #
resource "incus_network" "wan" {
  name    = "factory-wan"
  type    = "bridge"
  project = "default"

  config = {
    "ipv4.dhcp"    = "true"
    "ipv4.address" = "198.18.220.1/24"
    "ipv4.nat"     = "true"
    "ipv6.nat"     = "true"
  }
}

# LAN Network (For Targets) #
resource "incus_network" "lan" {
  name    = "factory-lan"
  type    = "bridge"
  project = "default"

  config = {
    "ipv4.dhcp"    = "false"
    "ipv4.address" = "198.18.210.1/24"
    "ipv4.nat"     = "true"
    "ipv6.address" = "none"
  }
}



### INSTANCES ###

# Router Container
resource "incus_instance" "router" {
  name             = "Router-Firewall"
  image            = incus_image.factory_debian.fingerprint
  project          = incus_project.factory.name
  profiles         = [incus_profile.factory_base.name]
  running          = true
  wait_for_network = false

  config = {
    "user.network-config" = <<EOF
version: 2
ethernets:
  eth0:
    addresses:
      - 198.18.220.254/24
    routes:
      - to: 0.0.0.0/0
        via: 198.18.220.1
    nameservers:
      addresses: [8.8.8.8, 8.8.4.4]
  eth1:
    addresses:
      - 198.18.210.10/24
EOF
    "user.user-data"      = <<EOF
#cloud-config
packages:
  - ifupdown
  - dnsmasq
  - iptables
  - iptables-persistent

write_files:
  - path: /etc/dnsmasq.conf
    content: |
      interface=eth1
      bind-interfaces
      dhcp-broadcast
      dhcp-range=198.18.210.50,198.18.210.100,12h
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

      # Block WAN (198.18.220.0/24) to LAN (198.18.210.0/24)
      -A FORWARD -s 198.18.220.0/24 -d 198.18.210.0/24 -j DROP

      # Block LAN (198.18.210.0/24) to WAN (198.18.220.0/24)
      -A FORWARD -s 198.18.210.0/24 -d 198.18.220.0/24 -j DROP

      # Allow LAN to Internet (not to WAN subnet)
      -A FORWARD -s 198.18.210.0/24 -j ACCEPT

      # Allow WAN to Internet (not to LAN subnet)
      -A FORWARD -s 198.18.220.0/24 -j ACCEPT

      COMMIT

runcmd:
  - sleep 5
  - sysctl -p
  - systemctl restart dnsmasq
  - iptables-restore < /etc/iptables/rules.v4
  - systemctl enable netfilter-persistent
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
  name             = "Attacker-external"
  image            = incus_image.factory_debian.fingerprint
  project          = incus_project.factory.name
  profiles         = [incus_profile.factory_base.name]
  running          = true
  wait_for_network = false

  depends_on = [incus_instance.router]

  config = {
    "limits.cpu"          = "4"
    "limits.memory"       = "8GiB"
    "user.network-config" = <<EOF
version: 2
ethernets:
  eth0:
    addresses:
      - 198.18.220.10/24
    routes:
      - to: 0.0.0.0/0
        via: 198.18.220.1
    nameservers:
      addresses: [8.8.8.8, 8.8.4.4]
EOF
    "user.user-data"      = <<EOF
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
  - ip route add 198.18.210.0/24 via 198.18.220.254

  # Make route persistent
  - echo "up ip route add 198.18.210.0/24 via 198.18.220.254 2>/dev/null || true" >> /etc/network/interfaces
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
  name             = "Attacker-internal"
  image            = incus_image.factory_debian.fingerprint
  project          = incus_project.factory.name
  profiles         = [incus_profile.factory_base.name]
  running          = true
  wait_for_network = false

  depends_on = [incus_instance.router]

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }

  config = {
    "user.network-config" = <<EOF
version: 2
ethernets:
  eth0:
    addresses:
      - 198.18.210.49/24
    routes:
      - to: 0.0.0.0/0
        via: 198.18.210.10
    nameservers:
      addresses: [198.18.210.10]
EOF
  }
}



### FACTORY LAN ASSETS ###

locals {
  factory_assets = {
    operator_workstation = {
      name = "Operator-Workstation"
      ip   = "198.18.210.20"
      role = "Factory operator workstation"
    }
    admin_paw = {
      name = "Admin-PAW"
      ip   = "198.18.210.21"
      role = "Privileged administration workstation"
    }
    jump_server = {
      name = "Jump-Server"
      ip   = "198.18.210.22"
      role = "Administrative bastion"
    }
    identity_server = {
      name = "Identity-Server"
      ip   = "198.18.210.23"
      role = "Identity, directory, and PKI infrastructure"
    }
    file_server = {
      name = "File-Server"
      ip   = "198.18.210.24"
      role = "Central factory file storage"
    }
    application_database = {
      name = "Application-Database"
      ip   = "198.18.210.25"
      role = "Application and database server"
    }
    backup_server = {
      name = "Backup-Server"
      ip   = "198.18.210.26"
      role = "Backup and recovery infrastructure"
    }
    cyber_monitor = {
      name = "Cyber-Monitor"
      ip   = "198.18.210.27"
      role = "IDS, SIEM, and security monitoring"
    }
    internal_workstation = {
      name = "Internal-Workstation"
      ip   = "198.18.210.28"
      role = "Standard internal user workstation"
    }
    hr_workstation = {
      name = "HR-Workstation"
      ip   = "198.18.210.29"
      role = "Human resources workstation"
    }
    engineering_workstation = {
      name = "Engineering-Workstation"
      ip   = "198.18.210.30"
      role = "PLC and controller engineering workstation"
    }
    historian_server = {
      name = "Historian-Server"
      ip   = "198.18.210.31"
      role = "Process history storage"
    }
    scada_server = {
      name = "SCADA-Server"
      ip   = "198.18.210.32"
      role = "Factory SCADA server"
    }
    operation_monitoring = {
      name = "Operation-Monitoring"
      ip   = "198.18.210.33"
      role = "Production and alarm monitoring"
    }
    hmi_line_1 = {
      name = "HMI-Line-1"
      ip   = "198.18.210.34"
      role = "Production line 1 HMI"
    }
    hmi_line_2 = {
      name = "HMI-Line-2"
      ip   = "198.18.210.35"
      role = "Production line 2 HMI"
    }
    plc_line_1 = {
      name = "PLC-Line-1"
      ip   = "198.18.210.40"
      role = "Production line 1 PLC"
    }
    plc_line_2 = {
      name = "PLC-Line-2"
      ip   = "198.18.210.41"
      role = "Production line 2 PLC"
    }
    industrial_gateway = {
      name = "Industrial-Gateway"
      ip   = "198.18.210.42"
      role = "RTU and industrial protocol gateway"
    }
    iot_sensor = {
      name = "IoT-Sensor"
      ip   = "198.18.210.43"
      role = "Factory IoT sensor"
    }
    factory_camera = {
      name = "Factory-Camera"
      ip   = "198.18.210.45"
      role = "Factory surveillance camera"
    }
    video_management = {
      name = "Video-Management"
      ip   = "198.18.210.46"
      role = "NVR and video management system"
    }
    badge_reader = {
      name = "Badge-Reader"
      ip   = "198.18.210.47"
      role = "Physical access control reader"
    }
    facility_bms = {
      name = "Facility-BMS"
      ip   = "198.18.210.48"
      role = "Building, HVAC, and power management"
    }
  }
}

# Lightweight containers representing the factory's IT and OT assets. These
# instances provide named, addressable systems without emulating real devices.
resource "incus_instance" "factory_asset" {
  for_each = local.factory_assets

  name             = each.value.name
  image            = incus_image.factory_debian.fingerprint
  project          = incus_project.factory.name
  profiles         = [incus_profile.factory_base.name]
  type             = "container"
  running          = true
  wait_for_network = false

  depends_on = [incus_instance.router]

  config = {
    "limits.cpu"          = "1"
    "limits.memory"       = "256MiB"
    "user.factory-role"   = each.value.role
    "user.network-config" = <<EOF
version: 2
ethernets:
  eth0:
    addresses:
      - ${each.value.ip}/24
    routes:
      - to: 0.0.0.0/0
        via: 198.18.210.10
    nameservers:
      addresses: [198.18.210.10]
EOF
  }

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = incus_network.lan.name
    }
  }
}
