# Reproducible: pinned base, no build args that change the output, and the
# binary is the only thing in the final image. A reviewer comparing a published
# image against this file should get the same bytes.
#
# THAT CLAIM WAS THREE FLAGS SHORT, and each of the three was measured rather
# than assumed:
#
#   golang:1.27.1  `1.27` floats to whatever patch is current on the day, and a
#                  Go patch release changes the compiler, so it changes the
#                  bytes. go.mod pins 1.27.1 and this must say the same
#   -buildvcs      Go stamps the commit into the binary by default and OMITS it
#                  silently where there is no .git. This context has none, so
#                  the same source built here and in a checkout differed
#   GOAMD64        changes code generation and can be set in an environment
#                  without anybody remembering it is
FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY cmd ./cmd
ARG VERSION=dev
RUN CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /heliograph-relay ./cmd/heliograph-relay

# The spool directory, made here because a scratch image has no shell to make it
# later and no way to chown it at run time.
#
# It matters that this exists in the image even though nothing is stored in it:
# Docker initialises an empty named volume from the image's directory, ownership
# included. Without it the volume arrives owned by root, the relay runs as 65532,
# and `-e HELIOGRAPH_RELAY_SPOOL=...` refuses to start with a permission error -
# which is the correct refusal to an impossible request, and a terrible first
# five minutes for a self-hoster following the README.
RUN install -d -o 65532 -g 65532 /var/lib/heliograph-relay

# scratch, not alpine. There is no shell, no package manager and nothing to
# exec into: if this container is compromised, there is nothing in it to use.
FROM scratch
COPY --from=build /heliograph-relay /heliograph-relay
COPY --from=build --chown=65532:65532 /var/lib/heliograph-relay /var/lib/heliograph-relay
# Non-root by uid, since there is no /etc/passwd to name a user in.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/heliograph-relay"]
