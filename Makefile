all: push

TAG=0.0.2
PREFIX?=getwhale/authproxy
ARCH?=amd64

server: main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) GOARM=6 go build -a -installsuffix cgo -ldflags '-w -s' -o server

container: server
	docker build --pull -t $(PREFIX):$(TAG) . --no-cache

push: container
	docker push $(PREFIX):$(TAG)

clean:
	rm -f server