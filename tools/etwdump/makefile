MAIN_BASEN_SRC=etwdump
RELEASE=$(GOPATH)/release/$(MAIN_BASEN_SRC)
VERSION=$(shell git tag | tail -1 | sed 's/^v//')
COMMITID=$(shell git rev-parse HEAD)

# Strips symbols and dwarf to make binary smaller
OPTS=-ldflags "-s -w"
ifdef DEBUG
	OPTS=
endif

all:
	$(MAKE) clean
	$(MAKE) init
	$(MAKE) buildversion
	$(MAKE) compile

init:
	mkdir -p $(RELEASE)/windows

compile:
	$(MAKE) windows

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-v$(VERSION)-386.exe *.go
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-v$(VERSION)-amd64.exe *.go
	cd $(RELEASE)/windows; shasum -a 256 * > sha256.txt

buildversion:
	printf "package main\n\nconst(\n    version=\"$(VERSION)\"\n    commitID=\"$(COMMITID)\"\n)\n" > version.go

clean:
	rm -rf $(RELEASE)/*