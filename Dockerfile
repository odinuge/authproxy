FROM scratch

COPY server /

EXPOSE 8080

ENTRYPOINT ["/server"]