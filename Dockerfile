FROM scratch

COPY target/x86_64-unknown-linux-gnu/release/acme-dns-hetzner /acme-dns-hetzner

ENTRYPOINT ["/acme-dns-hetzner"]
