FROM scratch

ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/ca-certificates.crt
COPY server /

EXPOSE 8080

ENTRYPOINT ["/server"]
