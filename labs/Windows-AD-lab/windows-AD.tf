terraform {
  required_providers {
    incus = {
      source  = "lxc/incus"
      version = "0.2.0"
    }
  }
}

provider "incus" {}

locals {
  wan_network = "incus-wan-win"
  lan_network = "incus-lan-win"
}

### NETWORKS ###

resource "incus_network" "wan" {
  name = local.wan_network
  type = "bridge"

  config = {
    "ipv4.dhcp"    = "true"
    "ipv4.address" = "198.19.100.1/24"
    "ipv4.nat"     = "true"
    "ipv6.nat"     = "true"
  }
}

resource "incus_network" "lan" {
  name = local.lan_network
  type = "bridge"

  config = {
    "ipv4.dhcp"    = "false"
    "ipv4.address" = "198.19.200.1/24"
    "ipv4.nat"     = "true"
    "ipv6.address" = "none"
  }
}



### INSTANCES ###

# Router Container
resource "incus_instance" "router" {
  name    = "Router-Firewall"
  image   = "images:debian/13/cloud"
  running = true
  wait_for_network = false
  project = "Windows-AD"

  depends_on = [incus_network.wan, incus_network.lan]

  config = {
    "user.network-config" = <<EOF
version: 2
ethernets:
  eth0:
    addresses:
      - 198.19.100.254/24
    routes:
      - to: 0.0.0.0/0
        via: 198.19.100.1
    nameservers:
      addresses: [8.8.8.8, 8.8.4.4]
  eth1:
    addresses:
      - 198.19.200.10/24
EOF
    "user.user-data" = <<EOF
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
      dhcp-range=198.19.200.50,198.19.200.100,12h
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

      # Block WAN (198.19.100.0/24) to LAN (198.19.200.0/24)
      -A FORWARD -s 198.19.100.0/24 -d 198.19.200.0/24 -j DROP

      # Block LAN (198.19.200.0/24) to WAN (198.19.100.0/24)
      -A FORWARD -s 198.19.200.0/24 -d 198.19.100.0/24 -j DROP

      # Allow LAN to Internet (not to WAN subnet)
      -A FORWARD -s 198.19.200.0/24 -j ACCEPT

      # Allow WAN to Internet (not to LAN subnet)
      -A FORWARD -s 198.19.100.0/24 -j ACCEPT

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
      parent  = local.wan_network
    }
  }

  device {
    name = "eth1"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = local.lan_network
    }
  }

  device {
    name = "root"
    type = "disk"
    properties = {
      path = "/"
      pool = "incus-storage"
    }
  }
}

# Attacker external (WAN) #
resource "incus_instance" "attacker-external" {
  name    = "Attacker-external"
  image   = "images:debian/13/cloud"
  running = true
  project = "Windows-AD"

  depends_on = [incus_instance.router]

  config = {
    "limits.cpu"    = "4"
    "limits.memory" = "8GiB"
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
  - ip route add 198.19.200.0/24 via 198.19.100.254

  # Make route persistent
  - echo "up ip route add 198.19.200.0/24 via 198.19.100.254 2>/dev/null || true" >> /etc/network/interfaces
EOF
  }

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = local.wan_network
    }
  }

  device {
    name = "root"
    type = "disk"
    properties = {
      path = "/"
      pool = "incus-storage"
    }
  }
}

# Attacker internal (LAN) #
resource "incus_instance" "attacker-internal" {
  name    = "Attacker-internal"
  image   = "images:debian/13/cloud"
  running = true
  project = "Windows-AD"

  depends_on = [incus_network.lan]

  device {
    name = "eth0"
    type = "nic"
    properties = {
      nictype = "bridged"
      parent  = local.lan_network
    }
  }

  device {
    name = "root"
    type = "disk"
    properties = {
      path = "/"
      pool = "incus-storage"
    }
  }

  config = {
    "user.user-data" = <<EOF
#cloud-config
bootcmd:
  - rm -f /etc/resolv.conf
  - echo "nameserver 198.19.200.1" > /etc/resolv.conf

runcmd:
  - dhclient eth0
EOF
  }
}
      

# Windows VM 1 (LAN) #
resource "incus_instance" "windows_client1" {
  name   = "WindowsClient1"
  type   = "virtual-machine"
  running = true
  profiles = ["default"]
  wait_for_network = false
  project = "Windows-AD"

  depends_on = [incus_network.lan]

  source_instance = {
    name     = "windows-template"
    project  = "default"
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
      parent  = local.lan_network
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


# Windows VM 2 (LAN) #
resource "incus_instance" "windows_client2" {
  name   = "WindowsClient2"
  type   = "virtual-machine"
  running = true
  profiles = ["default"]
  wait_for_network = false
  project = "Windows-AD"

  depends_on = [incus_network.lan]

  source_instance = {
    name     = "windows-template"
    project  = "default"
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
      parent  = local.lan_network
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


# Windows DC (LAN) #
resource "incus_instance" "windows_dc" {
  name   = "WindowsDC"
  type   = "virtual-machine"
  running = true
  profiles = ["default"]
  wait_for_network = false
  project = "Windows-AD"

  depends_on = [incus_network.lan]

  source_instance = {
    name     = "windows-server-template"
    project  = "default"
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
      parent  = local.lan_network
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
