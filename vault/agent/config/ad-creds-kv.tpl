{
  "username": "{{ with secret "kv/data/python_app" }}{{ .Data.data.username }}{{ end }}",
  "password": "{{ with secret "kv/data/python_app" }}{{ .Data.data.password }}{{ end }}"
}
