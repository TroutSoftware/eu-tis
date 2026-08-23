resource "incus_project" "ics_simulation" {
  name        = local.project_name
  description = "Segmented ICS simulation lab project."

  config = {
    "features.images"          = "false"
    "features.profiles"        = "true"
    "features.storage.buckets" = "false"
    "features.storage.volumes" = "false"
  }
}

resource "incus_network" "ics_networks" {
  for_each = local.networks

  project     = incus_project.ics_simulation.name
  name        = each.key
  description = each.value.description
  type        = "bridge"
  config      = each.value.config
}

resource "incus_profile" "ics_base" {
  project     = incus_project.ics_simulation.name
  name        = "ics-base"
  description = "Project-local base profile with root disk and conservative default sizing."

  config = {
    "boot.autostart" = "true"
    "limits.cpu"     = "1"
    "limits.memory"  = "1GiB"
  }

  device {
    name = "root"
    type = "disk"
    properties = {
      path = "/"
      pool = var.storage_pool
    }
  }
}

resource "incus_instance" "fw01" {
  project  = incus_project.ics_simulation.name
  name     = "fw01"
  image    = local.instances["fw01"].image
  type     = "container"
  running  = true
  profiles = [incus_profile.ics_base.name]

  config = {
    "boot.autostart"        = "true"
    "limits.cpu"            = tostring(local.instances["fw01"].cpu)
    "limits.memory"         = local.instances["fw01"].memory
    "linux.kernel_modules"  = "nf_tables"
    "user.access_interface" = "eth0"
    "cloud-init.user-data" = templatefile("${path.module}/templates/cloud-init-user-data.tftpl", {
      hostname       = "fw01"
      packages       = local.instances["fw01"].cloud_init_packages
      ssh_public_key = var.ssh_public_key
      write_files    = local.instances["fw01"].cloud_init_write_files
      runcmd         = local.instances["fw01"].cloud_init_runcmd
    })
    "cloud-init.network-config" = templatefile("${path.module}/templates/cloud-init-network-config.tftpl", {
      interfaces = local.instances["fw01"].interfaces
    })
  }

  dynamic "device" {
    for_each = local.instances["fw01"].interfaces

    content {
      name = device.value.name
      type = "nic"
      properties = {
        nictype = "bridged"
        parent  = incus_network.ics_networks[device.value.network].name
      }
    }
  }

  wait_for {
    type = "ipv4"
    nic  = "eth0"
  }
}

moved {
  from = incus_instance.lab_nodes["fw01"]
  to   = incus_instance.fw01
}

resource "terraform_data" "fw01_cloud_init_ready" {
  input = incus_instance.fw01.name

  provisioner "local-exec" {
    command = "${path.module}/../scripts/wait_for_cloud_init.sh ${incus_project.ics_simulation.name} ${incus_instance.fw01.name}"
  }
}

resource "incus_instance" "lab_nodes" {
  for_each = {
    for hostname, node in local.instances : hostname => node
    if hostname != "fw01"
  }

  project  = incus_project.ics_simulation.name
  name     = each.key
  image    = each.value.image
  type     = "container"
  running  = true
  profiles = [incus_profile.ics_base.name]

  config = merge(
    {
      "boot.autostart"        = "true"
      "limits.cpu"            = tostring(each.value.cpu)
      "limits.memory"         = each.value.memory
      "user.access_interface" = "eth0"
      "cloud-init.user-data" = templatefile("${path.module}/templates/cloud-init-user-data.tftpl", {
        hostname       = each.key
        packages       = each.value.cloud_init_packages
        ssh_public_key = var.ssh_public_key
        write_files    = each.value.cloud_init_write_files
        runcmd         = each.value.cloud_init_runcmd
      })
      "cloud-init.network-config" = templatefile("${path.module}/templates/cloud-init-network-config.tftpl", {
        interfaces = each.value.interfaces
      })
    }
  )

  depends_on = [terraform_data.fw01_cloud_init_ready]

  dynamic "device" {
    for_each = each.value.interfaces

    content {
      name = device.value.name
      type = "nic"
      properties = {
        nictype = "bridged"
        parent  = incus_network.ics_networks[device.value.network].name
      }
    }
  }

  wait_for {
    type = "ipv4"
    nic  = "eth0"
  }
}
