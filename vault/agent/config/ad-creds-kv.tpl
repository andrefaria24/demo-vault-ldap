{
  "username": "{{ with secret "kv/data/powershell_helloworld_app" }}{{ .Data.data.username }}{{ end }}",
  "password": "{{ with secret "kv/data/powershell_helloworld_app" }}{{ .Data.data.password }}{{ end }}"
}
