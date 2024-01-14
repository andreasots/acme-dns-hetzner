FROM scratch

COPY target/x86_64-unknown-linux-musl/release/acme-dns-hetzner /acme-dns-hetzner

ENTRYPOINT ["/acme-dns-hetzner"]
