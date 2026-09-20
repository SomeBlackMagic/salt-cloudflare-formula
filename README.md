# Cloudflare Salt Formula

Salt formula for declarative management of Cloudflare DNS zones and records.

## Installation

1. Copy `_states/cloudflare_dns.py` into `/srv/salt/_states` and
   `_modules/cloudflare_dns.py` into `/srv/salt/_modules` (or do the equivalent
   if you use a different layout for `file_roots` on Salt master).

2. Sync module and state caches on the minion you plan to use for managing zones:

   ```
   salt-call saltutil.sync_modules
   salt-call saltutil.sync_states
   ```

## Managing DNS records

### Authentication

Two authentication methods are supported:

**API Token (recommended)**

Create a token with `DNS:Edit` permission for the target zone at
[Cloudflare Dashboard → API Tokens](https://dash.cloudflare.com/profile/api-tokens).

```yaml
cloudflare_zones:
  example.com:
    api_token: "your_api_token_here"
    zone_id: "0101deadbeefdeadbeefdeadbeefdead"
    records: []
```

**Global API Key (legacy)**

Obtain the key at [My Account](https://dash.cloudflare.com/profile).
You can use a dedicated account with `DNS Administrator` permissions
if your account is a multi-user organization.

```yaml
cloudflare_zones:
  example.com:
    auth_email: admin@example.com
    auth_key: "global_api_key_here"
    zone_id: "0101deadbeefdeadbeefdeadbeefdead"
    records: []
```

The Zone ID can be found on the zone overview page in the Cloudflare dashboard.

### State file

Write the state like this (call it `cloudflare_dns.sls`):

```yaml
example.com:
  cloudflare_dns.manage_zone_records:
    - zone: {{ pillar["cloudflare_zones"]["example.com"]|yaml }}
```

### Pillar configuration

```yaml
cloudflare_zones:
  example.com:
    api_token: "your_api_token_here"
    zone_id: "0101deadbeefdeadbeefdeadbeefdead"
    # Optional: records matching regexes below are ignored by this state.
    exclude:
      - "^_acme-challenge\\..*"
      - "^external\\..*"
    records:
      - name: example.com
        type: A
        content: 93.184.216.34
        proxied: true
      - name: www.example.com
        type: CNAME
        content: example.com
        proxied: true
      - name: mail.example.com
        type: A
        content: 198.51.100.25
        proxied: false
        ttl: 300
      - name: example.com
        type: MX
        content: mail.example.com
        priority: 10
        proxied: false
        ttl: 300
      - name: example.com
        type: CAA
        content: '0 issue "letsencrypt.org"'
        proxied: false
        ttl: 3600
      - name: legacy.example.com
        type: A
        content: 203.0.113.50
        salt_managed: false
```


### Record fields

| Field          | Required | Default | Description                                              |
|----------------|----------|---------|----------------------------------------------------------|
| `name`         | yes      |         | Domain name (including zone, e.g. `sub.example.com`)     |
| `content`      | yes      |         | Value of the record                                      |
| `type`         | no       | `A`     | Record type: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SRV`, `CAA` |
| `proxied`      | no       | `false` | Whether the record is proxied through Cloudflare         |
| `ttl`          | no       | `1`     | TTL in seconds (`1` = auto). Minimum `120` for non-auto  |
| `priority`     | no       |         | Priority (required for `MX` records)                     |
| `salt_managed` | no       | `true`  | If `false`, the record is kept in Cloudflare but not managed by Salt |

### Exclude patterns

The `exclude` list accepts Python regexes. Records whose names match any pattern
are completely ignored — they will not be added, updated, or removed by this state.
Useful for ACME challenges, records managed by external tools, etc.

### Usage

Use Salt PGP renderer if you can to encrypt credentials in pillar:
https://docs.saltstack.com/en/latest/ref/renderers/all/salt.renderers.gpg.html

Dry run:

```
salt-call state.apply cloudflare_dns test=true
```

Apply:

```
salt-call state.apply cloudflare_dns
```

## License

[MIT](LICENSE)
