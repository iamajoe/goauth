GOCMD=go

GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

all: help

.PHONY:install
install: ## Install dependencies
	@$(GOCMD) install github.com/pressly/goose/v3/cmd/goose@latest
	@$(GOCMD) install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	@make build_sql
	@$(GOCMD) get ./...
	@$(GOCMD) mod vendor
	@$(GOCMD) mod tidy
	@$(GOCMD) mod download

.PHONY:build_sql
build_sql: ## Builds sql query files
	DB_HOST=$$DB_HOST DB_USER=$$DB_USER DB_PASSWORD=$$DB_PASSWORD DB_NAME=$$DB_NAME sqlc generate

test_all: ## Run the tests of the project
	@make vet
	@make lint
	@make test_race_coverage

test: ## Runs the tests of the project
	ENV=test $(GOCMD) test ./... -count=1 -v

test_fn: ## Runs the tests on a function
	ENV=test $(GOCMD) test ./... -count=1 -v -run "$(filter-out $@,$(MAKECMDGOALS))"

test_race_coverage: ## Runs the tests with race and coverage
	$(GOCMD) test -race ./... -coverprofile=coverage.out

vet: ## Vets the project
	$(GOCMD) vet -v

lint: ## Lints the project
	golines -w -l .
	goimports -w -l .
	gofumpt -l -w .

.PHONY: help
help: ## Show this help.
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "    ${YELLOW}%-20s${GREEN}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST)
