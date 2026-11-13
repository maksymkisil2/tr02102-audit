# Helper image for the lab: certificate generation and the smoke test.
FROM alpine:3.24

RUN apk add --no-cache openssl
