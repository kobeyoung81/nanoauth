FROM golang:1.24-alpine AS builder

WORKDIR /src
RUN go env -w GOPROXY=https://goproxy.cn,direct
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /bin/nanoauth ./cmd/nanoauth

FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/nanoauth /usr/local/bin/nanoauth

EXPOSE 8081

ENTRYPOINT ["nanoauth"]
