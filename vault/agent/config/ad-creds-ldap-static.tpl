{
  "username": "{{ with secret "ldap/static-cred/python-static" }}{{ .Data.username }}{{ end }}",
  "password": "{{ with secret "ldap/static-cred/python-static" }}{{ .Data.password }}{{ end }}"
}

