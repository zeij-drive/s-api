FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/starryapi ./cmd/server && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder --chown=nonroot:nonroot /out/starryapi /starryapi
COPY --from=builder --chown=nonroot:nonroot /out/data /data
ENV ADDR=:8080 STORE_PATH=/data/state.json
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/starryapi"]
