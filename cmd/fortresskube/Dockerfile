# Built from a prebuilt static binary: docker build -f cmd/fortresskube/Dockerfile DIR,
# where DIR holds only the fortresskube binary. The base ships the system CA
# bundle at /etc/ssl/certs/ca-certificates.crt for a Let's Encrypt tunnel cert.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY fortresskube /fortresskube
ENTRYPOINT ["/fortresskube"]
