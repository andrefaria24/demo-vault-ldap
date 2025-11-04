{
  "username": "{{ with secret "ldap/static-cred/powershell-static" }}{{ .Data.username }}{{ end }}",
  "password": "{{ with secret "ldap/static-cred/powershell-static" }}{{ .Data.password }}{{ end }}"
}

