### OPTIONAL OWASP TARGETS ###

variable "enable_juice_shop" {
  description = "Create the optional OWASP Juice Shop container on the LAN."
  type        = bool
  default     = false
}

variable "enable_webgoat" {
  description = "Create the optional OWASP WebGoat container on the LAN."
  type        = bool
  default     = false
}

# OWASP Juice Shop (LAN) #
resource "incus_instance" "juice_shop" {
  count = var.enable_juice_shop ? 1 : 0

  name    = "JuiceShop"
  image   = "images:debian/13/cloud"
  type    = "container"
  running = true

  config = {
    "security.nesting"                     = "true"
    "security.syscalls.intercept.mknod"    = "true"
    "security.syscalls.intercept.setxattr" = "true"
    "cloud-init.user-data"                 = <<EOF
#cloud-config
package_update: true
packages:
  - docker.io
  - iputils-ping
  - curl

bootcmd:
  - rm -f /etc/resolv.conf
  - echo "nameserver 198.18.200.1" > /etc/resolv.conf

runcmd:
  - systemctl enable --now docker
  - docker rm -f juice-shop || true
  - docker run -d --restart unless-stopped --name juice-shop -p 3000:3000 bkimminich/juice-shop
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

# OWASP WebGoat (LAN) #
resource "incus_instance" "webgoat" {
  count = var.enable_webgoat ? 1 : 0

  name    = "WebGoat"
  image   = "images:debian/13/cloud"
  type    = "container"
  running = true

  config = {
    "security.nesting"                     = "true"
    "security.syscalls.intercept.mknod"    = "true"
    "security.syscalls.intercept.setxattr" = "true"
    "cloud-init.user-data"                 = <<EOF
#cloud-config
package_update: true
packages:
  - docker.io
  - iputils-ping
  - curl

bootcmd:
  - rm -f /etc/resolv.conf
  - echo "nameserver 198.18.200.1" > /etc/resolv.conf

runcmd:
  - systemctl enable --now docker
  - docker rm -f webgoat || true
  - docker run -d --privileged --restart unless-stopped --name webgoat -p 8080:8080 -p 9090:9090 webgoat/webgoat
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
