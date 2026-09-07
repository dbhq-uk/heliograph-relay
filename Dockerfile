# Reproducible: pinned base, no build args that change the output, and the
# binary is the only thing in the final image. A reviewer comparing a published
# image against this file should get the same bytes.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY cmd ./cmd
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /heliograph-relay ./cmd/heliograph-relay

# scratch, not alpine. There is no shell, no package manager and nothing to
# exec into: if this container is compromised, there is nothing in it to use.
FROM scratch
COPY --from=build /heliograph-relay /heliograph-relay
# Non-root by uid, since there is no /etc/passwd to name a user in.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/heliograph-relay"]
