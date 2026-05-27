resource "hetznerrobot_firewall" "firewall" {
  server_id     = 1234567
  active        = true
  whitelist_hos = true
  # Set true to also evaluate IPv6 packets against the rule list. When false
  # (Hetzner default), IPv6 traffic bypasses all rules.
  filter_ipv6 = true

  # Each rule defaults to ip_version = "ipv4" if not specified, matching the
  # behavior of pre-1.5.0 versions of this provider. Per the Hetzner API,
  # `ip_version` is required whenever `protocol` is set on a rule.
  rule {
    name     = "icmp"
    protocol = "icmp"
    action   = "accept"
  }

  rule {
    name     = "ssh"
    protocol = "tcp"
    dst_port = "22"
    action   = "accept"
  }

  # IPv6 variant of the SSH rule.
  rule {
    ip_version = "ipv6"
    name       = "ssh-v6"
    protocol   = "tcp"
    dst_port   = "22"
    action     = "accept"
  }

  rule {
    name   = "Deny others"
    action = "discard"
  }
}
