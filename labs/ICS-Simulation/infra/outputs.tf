output "project_name" {
  description = "Incus project used for the lab."
  value       = incus_project.ics_simulation.name
}

output "hosts" {
  description = "Hostnames mapped to static IPv4 addresses and intended Ansible groups."
  value = {
    for hostname, node in local.instances : hostname => {
      ipv4           = node.primary
      ansible_groups = node.groups
    }
  }
}
