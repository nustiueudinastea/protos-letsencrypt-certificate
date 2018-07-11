FROM golang:1.8.3 as builder
LABEL protos="0.0.1" \
      protos.installer.metadata.description="This applications provides SSL certificates using the letsencrypt.com service. " \
      protos.installer.metadata.capabilities="ResourceProvider,ResourceConsumer,InternetAccess,GetInformation" \
      protos.installer.metadata.requires="dns" \
      protos.installer.metadata.provides="certificate" \
      protos.installer.metadata.name="letsencrypt-certificate"

ADD . "/go/src/letsencrypt-certificate/"
WORKDIR "/go/src/letsencrypt-certificate/"
RUN go get -u github.com/golang/dep/cmd/dep
RUN dep ensure
RUN go build letsencrypt-certificate.go
RUN chmod +x /go/src/letsencrypt-certificate/start.sh

FROM alpine:latest
COPY --from=builder /go/src/letsencrypt-certificate/letsencrypt-certificate /root/
COPY --from=builder /go/src/letsencrypt-certificate/start.sh /root/
RUN chmod +x /root/start.sh

ENTRYPOINT ["/root/start.sh"]
