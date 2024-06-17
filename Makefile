VERSION := $(shell git describe --tags)
BUILD := $(shell git rev-parse --short HEAD)
PROJECT_NAME := $(shell basename "$(PWD)")
DT := $(shell date '+%Y%m%d%H%M%S')


## test: Run all unit-tests
test:
	go clean -testcache && go test -race -timeout 120s ./...


## dependencies: Sync dependencies
dependencies:
	go mod tidy


## format: Formats GO source code
bench:
	go clean -testcache && go test -benchmem -bench=. ./...


## format: Formats GO source code
format:
	go fmt ./...


all: help
help: Makefile
	@echo
	@echo "choose a command run in "$(PROJECT_NAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo


.PHONY: dependencies test bench help format
.DEFAULT_GOAL := help

