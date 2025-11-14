BINARY = myapp
VERSION ?= 0.1.0
SRC_DIR = src
OUTPUT = target/$(BINARY)-$(VERSION)
LDFLAGS = -ldflags "-X main.version=$(VERSION)"

.PHONY: build run clean

build:
	@mkdir -p target
	cd $(SRC_DIR) && go build $(LDFLAGS) -o ../$(OUTPUT)

run:
	cd $(SRC_DIR) && go run $(LDFLAGS) main.go

fclean:
	rm -rf target

re:	fclean	build
