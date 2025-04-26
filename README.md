<div align="center">
    <h1>Oxide WDNS</h1>
    <h4>🚀 A high-performance DNS gateway that supports both HTTPDNS and DNS-over-HTTPS (DoH), written in Rust.</h4>
	<img src="./images/logo.png" alt="logo">
</div>

```bash
cargo test --test doh_api_tests
cargo test --test rate_limit_tests
```

google dns-over-https

```bash
$ curl -s -H 'accept: application/dns+json' \
'https://dns.google.com/resolve?name=www.potaroo.net&type=A' | jq

{
    "Status": 0,
    "TC": false,
    "RD": true,
    "RA": true,
    "AD": true,
    "CD": false,
    "Question": [
        {
            "name": "www.potaroo.net.",
            "type": 1
        }
    ],
    "Answer": [
        {
            "name": "www.potaroo.net.",
            "type": 1,
            "TTL": 6399,
            "data": "203.133.248.2"
        }
    ],
    "Comment": "Response from 203.133.248.2."
}
```

rfc8484 dns-over-https

```bash
$ curl -s -H 'accept: application/dns-message' \
'https://cloudflare-dns.com/dns-query?name=www.potaroo.net&type=A' | hexdump -C
```

cargo test -p oxide-wdns server::config_tests
