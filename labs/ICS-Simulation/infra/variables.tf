variable "storage_pool" {
  description = "Existing Incus storage pool to use for the ics-base profile root disk."
  type        = string
}

variable "image_debian_cloud" {
  description = "Incus image reference for Debian cloud containers."
  type        = string
  default     = "images:debian/12/cloud"
}

variable "image_ubuntu_cloud" {
  description = "Incus image reference for Ubuntu cloud containers. Declared for optional extensions and OCI wrapper patterns."
  type        = string
  default     = "images:ubuntu/24.04/cloud"
}

variable "ssh_public_key" {
  description = "SSH public key injected into /home/lab/.ssh/authorized_keys by cloud-init."
  type        = string
  sensitive   = true
}
