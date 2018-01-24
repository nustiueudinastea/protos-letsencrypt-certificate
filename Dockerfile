FROM golang:1.9
LABEL protos="0.0.1" \
      protos.installer.metadata.description="This applications provides SSL certificates using the letsencrypt.com service. " \
      protos.installer.metadata.capabilities="ResourceProvider,InternetAccess,InternetListen" \
      protos.installer.metadata.provides="certificate"

ADD . "/go/src/letsencrypt-certificate/"
WORKDIR "/go/src/letsencrypt-certificate/"
RUN curl https://glide.sh/get | sh
RUN glide update --strip-vendor
RUN go build letsencrypt-certificate.go
RUN chmod +x /go/src/letsencrypt-certificate/start.sh

ENTRYPOINT ["/go/src/letsencrypt-certificate/start.sh"]
