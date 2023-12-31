SHELL := /bin/sh

USER_UID ?= $(shell id -u)
USER_GID ?= $(shell id -g)
DOCKER ?= docker
DOCKER_COMPOSE ?= docker compose
DOCKER_COMPOSE_DEV ?= $(DOCKER_COMPOSE) -f docker-compose.dev.yml

export

.PHONY: dev/up
dev/up: clean
# Buildar e subir a stack local
	@$(DOCKER_COMPOSE_DEV) build $(DOCKER_BUILD_OPTS)
	@$(DOCKER_COMPOSE_DEV) up $(DOCKER_UP_OPTS) --remove-orphans --renew-anon-volumes -d
	@.dev/wait-for-success.sh nc -vz $(KDC_HOSTNAME) 88
	@sleep 3
	@.dev/wait-for-success.sh nc -vz $(KDC_HOSTNAME) 88
	@.dev/wait-for-success.sh make dev/kinit	

.PHONY: dev/logs
dev/logs:
# Logs da stack local
	$(DOCKER_COMPOSE_DEV) logs -f

.PHONY: dev/rm
dev/rm:
# Remover a stack local e limpar tudo
	$(DOCKER_COMPOSE_DEV) rm -fsv
	$(DOCKER) volume prune -f
	$(DOCKER) network prune -f

.PHONY: dev/kinit
dev/kinit:
	$(DOCKER_COMPOSE_DEV) exec kdc krb5-kinit $(DEV_KERBEROS_USER)

.PHONY: clean
clean:
	@rm -rf tests/stack/kdc/run/*.keytab tests/stack/kdc/run/*.tmp tests/stack/kdc/run/krb5.conf
