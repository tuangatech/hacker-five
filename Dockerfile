# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/hackerfive ./cmd/hackerfive

# ---- final stage ----
# distroless static (not scratch): this tool makes outbound HTTPS scan
# requests, so it needs the CA cert bundle distroless/static ships —
# scratch has none, and TLS verification would fail outright.
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/hackerfive /usr/local/bin/hackerfive
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/hackerfive"]
