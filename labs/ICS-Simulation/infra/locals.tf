locals {
  project_name = "ICS-simulation"

  networks = {
    "ics-wan" = {
      description = "WAN edge bridge with DHCP and NAT for the lab perimeter."
      config = {
        "ipv4.address" = "198.18.110.1/24"
        "ipv4.dhcp"    = "true"
        "ipv4.nat"     = "true"
        "ipv6.address" = "none"
      }
    }
    "ics-it" = {
      description = "IT segment."
      config = {
        "ipv4.address" = "198.18.10.1/24"
        "ipv4.dhcp"    = "false"
        "ipv4.nat"     = "false"
        "ipv6.address" = "none"
      }
    }
    "ics-ot-dmz" = {
      description = "OT DMZ segment."
      config = {
        "ipv4.address" = "198.18.20.1/24"
        "ipv4.dhcp"    = "false"
        "ipv4.nat"     = "false"
        "ipv6.address" = "none"
      }
    }
    "ics-ot-ops" = {
      description = "OT operations segment."
      config = {
        "ipv4.address" = "198.18.30.1/24"
        "ipv4.dhcp"    = "false"
        "ipv4.nat"     = "false"
        "ipv6.address" = "none"
      }
    }
    "ics-ot-cell" = {
      description = "OT cell/area segment."
      config = {
        "ipv4.address" = "198.18.40.1/24"
        "ipv4.dhcp"    = "false"
        "ipv4.nat"     = "false"
        "ipv6.address" = "none"
      }
    }
  }

  instances = {
    "fw01" = {
      image               = var.image_debian_cloud
      cpu                 = 2
      memory              = "2GiB"
      groups              = ["router", "router_firewall", "wan"]
      primary             = "198.18.110.254"
      cloud_init_packages = ["openssh-server", "sudo", "python3", "python3-apt", "dnsmasq", "nftables"]
      cloud_init_write_files = [
        {
          path        = "/etc/nftables.conf"
          permissions = "0644"
          content     = <<-EOT
            #!/usr/sbin/nft -f

            flush ruleset

            define wan_if = "eth0"
            define it_if = "eth1"
            define dmz_if = "eth2"
            define ops_if = "eth3"
            define cell_if = "eth4"

            table inet filter {
              chain input {
                type filter hook input priority filter; policy drop;

                iif "lo" accept
                ct state established,related accept
                ct state invalid drop

                ip protocol icmp accept
                ip6 nexthdr ipv6-icmp accept

                tcp dport 22 accept
                udp dport 53 accept
                tcp dport 53 accept
              }

              chain forward {
                type filter hook forward priority filter; policy drop;

                ct state established,related accept
                ct state invalid drop

                iifname { $it_if, $dmz_if, $ops_if, $cell_if } oifname $wan_if accept
                iifname $it_if oifname $dmz_if tcp dport 22 accept
                iifname $dmz_if oifname $ops_if tcp dport { 22, 443 } accept
                iifname $ops_if oifname $cell_if tcp dport 502 accept
                iifname $ops_if oifname $dmz_if tcp dport 1883 accept
                iifname $wan_if oifname { $it_if, $dmz_if, $ops_if, $cell_if } drop
              }

              chain output {
                type filter hook output priority filter; policy accept;
              }
            }

            table ip nat {
              chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;

                oifname $wan_if ip saddr { 198.18.10.0/24, 198.18.20.0/24, 198.18.30.0/24, 198.18.40.0/24 } masquerade
              }
            }
          EOT
        },
        {
          path        = "/etc/dnsmasq.d/ics-lab.conf"
          permissions = "0644"
          content     = <<-EOT
            domain-needed
            bogus-priv
            bind-interfaces
            cache-size=1000
            no-resolv

            interface=eth0
            interface=eth1
            interface=eth2
            interface=eth3
            interface=eth4

            listen-address=198.18.110.254
            listen-address=198.18.10.254
            listen-address=198.18.20.254
            listen-address=198.18.30.254
            listen-address=198.18.40.254

            server=1.1.1.1
            server=9.9.9.9
          EOT
        },
        {
          path        = "/etc/sysctl.d/99-ics-router.conf"
          permissions = "0644"
          content     = "net.ipv4.ip_forward=1\n"
        }
      ]
      cloud_init_runcmd = [
        ["sysctl", "--load=/etc/sysctl.d/99-ics-router.conf"],
        ["systemctl", "enable", "--now", "ssh"],
        ["systemctl", "enable", "--now", "nftables"],
        ["systemctl", "enable", "--now", "dnsmasq"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-wan"
          address     = "198.18.110.254/24"
          gateway     = "198.18.110.1"
          dns_servers = ["1.1.1.1", "9.9.9.9"]
        },
        {
          name        = "eth1"
          network     = "ics-it"
          address     = "198.18.10.254/24"
          gateway     = null
          dns_servers = []
        },
        {
          name        = "eth2"
          network     = "ics-ot-dmz"
          address     = "198.18.20.254/24"
          gateway     = null
          dns_servers = []
        },
        {
          name        = "eth3"
          network     = "ics-ot-ops"
          address     = "198.18.30.254/24"
          gateway     = null
          dns_servers = []
        },
        {
          name        = "eth4"
          network     = "ics-ot-cell"
          address     = "198.18.40.254/24"
          gateway     = null
          dns_servers = []
        }
      ]
    }
    "wan-test01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["wan_test", "wan"]
      primary                = "198.18.110.10"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-wan"
          address     = "198.18.110.10/24"
          gateway     = "198.18.110.254"
          dns_servers = ["198.18.110.254"]
        }
      ]
    }
    "it-file01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["file_servers", "it"]
      primary                = "198.18.10.10"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-it"
          address     = "198.18.10.10/24"
          gateway     = "198.18.10.254"
          dns_servers = ["198.18.10.254"]
        }
      ]
    }
    "it-ws01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["it_workstations", "it"]
      primary                = "198.18.10.20"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-it"
          address     = "198.18.10.20/24"
          gateway     = "198.18.10.254"
          dns_servers = ["198.18.10.254"]
        }
      ]
    }
    "it-activity01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["activity_agents", "it"]
      primary                = "198.18.10.30"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-it"
          address     = "198.18.10.30/24"
          gateway     = "198.18.10.254"
          dns_servers = ["198.18.10.254"]
        }
      ]
    }
    "otdmz-jump01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["jump_hosts", "ot_dmz"]
      primary                = "198.18.20.10"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-ot-dmz"
          address     = "198.18.20.10/24"
          gateway     = "198.18.20.254"
          dns_servers = ["198.18.20.254"]
        }
      ]
    }
    "otops-scada01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["scada", "ot_ops"]
      primary                = "198.18.30.10"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-ot-ops"
          address     = "198.18.30.10/24"
          gateway     = "198.18.30.254"
          dns_servers = ["198.18.30.254"]
        }
      ]
    }
    "otops-hmi01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["hmi", "ot_ops"]
      primary                = "198.18.30.20"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-ot-ops"
          address     = "198.18.30.20/24"
          gateway     = "198.18.30.254"
          dns_servers = ["198.18.30.254"]
        }
      ]
    }
    "otcell-plc01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["plc", "ot_cell"]
      primary                = "198.18.40.10"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-ot-cell"
          address     = "198.18.40.10/24"
          gateway     = "198.18.40.254"
          dns_servers = ["198.18.40.254"]
        }
      ]
    }
    "otcell-process01" = {
      image                  = var.image_debian_cloud
      cpu                    = 1
      memory                 = "1GiB"
      groups                 = ["process_simulators", "ot_cell"]
      primary                = "198.18.40.20"
      cloud_init_packages    = ["openssh-server", "sudo", "python3", "python3-apt"]
      cloud_init_write_files = []
      cloud_init_runcmd = [
        ["systemctl", "enable", "--now", "ssh"]
      ]
      interfaces = [
        {
          name        = "eth0"
          network     = "ics-ot-cell"
          address     = "198.18.40.20/24"
          gateway     = "198.18.40.254"
          dns_servers = ["198.18.40.254"]
        }
      ]
    }
  }
}
