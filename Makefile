PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SHRDIR ?= $(PREFIX)/share
DOCDIR ?= $(PREFIX)/share/doc
MANDIR ?= $(PREFIX)/share/man
MANS = $(basename $(wildcard docs/*.txt))

CGO_LDFLAGS := '$(LDFLAGS)'
CGO_CPPFLAGS := '$(CPPFLAGS)'
CGO_CFLAGS := '$(CFLAGS)'
GOFLAGS ?= -buildmode=pie -trimpath

SOURCES = $(shell go list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}' ./...)

all: build
build: gosiglist

gosiglist: $(SOURCES)
	go build -o $@ ./cmd/$@/...
