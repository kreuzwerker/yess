VERSION := "1.0.0"

BUILD := $(shell git rev-parse --short HEAD)
FLAGS	:= "-s -w -X=main.build=$(BUILD) -X=main.time=`TZ=UTC date '+%FT%TZ'` -X=main.version=$(VERSION)"
REPO := yess
TOKEN = $(shell cat .token)
USER := kreuzwerker

build/yess-darwin-amd64:
	@mkdir -p build
	GO111MODULES=on nice go build -o $@ -ldflags $(FLAGS) yess.go

build: build/yess-darwin-amd64
