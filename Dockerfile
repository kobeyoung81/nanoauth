# This module's front end: a module-federation remote the portal loads at runtime.
# It is built here so the image carries its own page; the portal's shell does not
# need rebuilding when this one changes.
FROM node:22-alpine AS ui

WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM golang:1.25-alpine AS builder

WORKDIR /src
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /bin/nanoauth ./cmd/nanoauth

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/nanoauth /usr/local/bin/nanoauth
COPY --from=ui /src/ui/dist /app/ui

ENV NANOAUTH_UI_DIR=/app/ui

EXPOSE 8081

ENTRYPOINT ["nanoauth"]
