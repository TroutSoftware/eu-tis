terraform {
  required_version = ">= 1.6.0"

  required_providers {
    incus = {
      source  = "lxc/incus"
      version = ">= 1.0.0"
    }
  }
}

provider "incus" {}
