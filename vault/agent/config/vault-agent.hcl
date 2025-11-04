pid_file = "./vault-agent.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "./role_id"
      secret_id_file_path = "./secret_id"
      remove_secret_id_file_after_reading = false
    }
  }
  sink "file" {
    wrap_ttl = "30m"
    config = {
      path = "./vault-token"
    }
  }
}

template {
  #source      = "./ad-creds-kv.tpl"
  source      = "./ad-creds-ldap-static.tpl"
  destination = "./ad-creds.json"
  create_dest_dirs = true
  perms = "0600"
  wait {
    min = "10s"
    max = "30s"
  }
}