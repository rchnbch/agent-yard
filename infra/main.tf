# One fixed yard host (v1: no autoscaling, no multi-host). Inbound traffic is
# denied by the Hetzner firewall; admin and HQ traffic arrive over Tailscale.
# No secrets in user-data: Hetzner's metadata service serves it, and
# sandboxes must not be able to read anything useful from it.

resource "hcloud_ssh_key" "admin" {
  name       = "${var.name}-admin"
  public_key = var.ssh_public_key
}

resource "hcloud_firewall" "yard" {
  name = "${var.name}-deny-inbound"

  # Hetzner firewalls deny all inbound traffic that no rule allows. The only
  # optional rule is a temporary SSH opening for the first bootstrap.
  dynamic "rule" {
    for_each = length(var.admin_ssh_cidrs) > 0 ? [1] : []
    content {
      description = "temporary bootstrap SSH"
      direction   = "in"
      protocol    = "tcp"
      port        = "22"
      source_ips  = var.admin_ssh_cidrs
    }
  }
}

resource "hcloud_server" "yard" {
  name         = var.name
  server_type  = var.server_type
  location     = var.location
  image        = var.image
  ssh_keys     = [hcloud_ssh_key.admin.id]
  firewall_ids = [hcloud_firewall.yard.id]

  public_net {
    ipv4_enabled = true # outbound egress for sandboxes; inbound is firewalled
    ipv6_enabled = true
  }

  # Deliberately no secrets: only a marker that the box is meant for
  # host/bootstrap. Everything sensitive is pushed later over SSH/Tailscale.
  user_data = <<-EOT
    #cloud-config
    write_files:
      - path: /etc/agent-yard-host
        content: "Provisioned for agent-yard; run host/bootstrap.\n"
  EOT

  labels = {
    role = "agent-yard"
  }
}

resource "hcloud_volume" "store" {
  count    = var.volume_size_gb > 0 ? 1 : 0
  name     = "${var.name}-store"
  size     = var.volume_size_gb
  location = var.location
  # Unformatted: host/bootstrap formats it XFS (prjquota) only if it is empty.
}

resource "hcloud_volume_attachment" "store" {
  count     = var.volume_size_gb > 0 ? 1 : 0
  volume_id = hcloud_volume.store[0].id
  server_id = hcloud_server.yard.id
  automount = false
}
