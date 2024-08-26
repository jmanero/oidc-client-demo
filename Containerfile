from docker.io/library/golang:alpine AS build

RUN mkdir /work
WORKDIR /work

RUN mkdir -p /build/bin /build/etc

COPY go.mod go.sum main.go .
COPY templates templates

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod go build -o /build/bin/server .

FROM scratch

COPY --from=build /build /
COPY --from=build /etc/ssl/certs /etc/ssl/certs
COPY static /static

ENTRYPOINT [ "/bin/server" ]
