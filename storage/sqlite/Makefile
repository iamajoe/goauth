GOCMD=go

.PHONY:install
install: ## Install dependencies
	@$(GOCMD) install github.com/sqlc-dev/sqlc/cmd/sqlc@latest

.PHONY:generate
generate: ## Generate sql queries
	@sqlc generate

