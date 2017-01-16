Usage: `hola [-secrets=secrets.yml]`

Runs a super simple authenticated service on port 4040.

Provide a JWT token using the key/secret pair to sign it and set the correct ISS claim.

See `hola-cli <key> <secret> [scopes...]` example interaction.

example `secrets.yml`

```yaml
- key: some-base-key
  secret: some-base-secret
  scopes: ['builds.read', 'projects.write']
  signing_method: 'HS256'
```
