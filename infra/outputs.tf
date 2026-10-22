output "ipv4" {
  description = "Public IPv4 (only for the first bootstrap; use Tailscale afterwards)."
  value       = hcloud_server.yard.ipv4_address
}

output "store_device" {
  description = "Pass as YARD_STORAGE_DEVICE to host/bootstrap."
  value       = var.volume_size_gb > 0 ? hcloud_volume.store[0].linux_device : ""
}
