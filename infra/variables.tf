variable "name" {
  description = "Server name (also its Tailscale hostname)."
  type        = string
  default     = "yard1"
}

variable "server_type" {
  description = "Hetzner server type. Chosen at apply time (prices and availability changed in June 2026); aim for ~8 vCPU / 16-32 GB amd64."
  type        = string
}

variable "location" {
  description = "Hetzner location, e.g. fsn1, nbg1, hel1."
  type        = string
}

variable "image" {
  description = "OS image. agent-yard requires Debian 13."
  type        = string
  default     = "debian-13"
}

variable "ssh_public_key" {
  description = "Admin SSH public key (contents, not a path)."
  type        = string
}

variable "admin_ssh_cidrs" {
  description = "CIDRs allowed to reach SSH from the internet. Keep [] (all inbound denied); set your /32 only for the first bootstrap, then apply again with []."
  type        = list(string)
  default     = []
}

variable "volume_size_gb" {
  description = "Size of the Hetzner volume holding the XFS container store (0 = no volume; bootstrap uses a loop file)."
  type        = number
  default     = 200
}
