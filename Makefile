APP_CONTAINER = securescan_app
DB_CONTAINER  = securescan_db
EXEC          = docker exec -it $(APP_CONTAINER)
CONSOLE       = $(EXEC) php bin/console

.DEFAULT_GOAL := help

.PHONY: help build up down restart logs logs-app logs-db logs-nginx sh db-sh \
	install db-create db-drop db-reset migration migrate migrate-status fixtures schema-validate \
	entity controller form crud voter subscriber command make-test \
	assets assets-list importmap-require importmap-audit \
	composer-install composer-update composer-show composer-audit \
	cache-clear routes route container-debug dotenv doctrine-mapping \
	test permissions

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

## ── Docker ───────────────────────────────────────────────────────────────

build: ## Build les conteneurs
	docker compose up -d --build

up: ## Démarre les conteneurs
	docker compose up -d

down: ## Arrête les conteneurs
	docker compose down

restart: down up ## Redémarre les conteneurs

logs: ## Logs de tous les conteneurs
	docker compose logs -f

logs-app: ## Logs du conteneur app
	docker compose logs -f app

logs-db: ## Logs du conteneur db
	docker compose logs -f database

logs-nginx: ## Logs du conteneur nginx
	docker compose logs -f nginx

sh: ## Ouvre un shell dans le conteneur PHP
	docker exec -it $(APP_CONTAINER) bash

db-sh: ## Ouvre un shell MySQL
	docker exec -it $(DB_CONTAINER) bash

## ── Installation ─────────────────────────────────────────────────────────

install: build composer-install db-create migrate fixtures assets ## Installation complète (première fois)

## ── Base de données ──────────────────────────────────────────────────────

db-create: ## Crée la base de données
	$(CONSOLE) doctrine:database:create

db-drop: ## Supprime la base de données
	$(CONSOLE) doctrine:database:drop --force

db-reset: db-drop db-create migrate fixtures ## Réinitialise complètement la BDD

migration: ## Crée une migration (après modification d'une entité)
	$(CONSOLE) make:migration

migrate: ## Lance les migrations
	$(CONSOLE) doctrine:migrations:migrate --no-interaction

migrate-status: ## Voit le statut des migrations
	$(CONSOLE) doctrine:migrations:status

fixtures: ## Charge les fixtures
	$(CONSOLE) doctrine:fixtures:load --no-interaction

schema-validate: ## Valide le schéma Doctrine
	$(CONSOLE) doctrine:schema:validate

## ── Génération de code ───────────────────────────────────────────────────

entity: ## Crée une entité
	$(CONSOLE) make:entity

controller: ## Crée un controller
	$(CONSOLE) make:controller

form: ## Crée un formulaire
	$(CONSOLE) make:form

crud: ## Crée un CRUD complet
	$(CONSOLE) make:crud

voter: ## Crée un voter
	$(CONSOLE) make:voter

subscriber: ## Crée un event subscriber
	$(CONSOLE) make:subscriber

command: ## Crée une commande custom
	$(CONSOLE) make:command

make-test: ## Crée un test
	$(CONSOLE) make:test

## ── Assets ────────────────────────────────────────────────────────────────

assets: ## Compile les assets pour la prod
	$(CONSOLE) asset-map:compile

assets-list: ## Liste les assets mappés
	$(CONSOLE) debug:asset-map

importmap-require: ## Installe un package JS (usage: make importmap-require pkg=nom-du-package)
	$(CONSOLE) importmap:require $(pkg)

importmap-audit: ## Audit des packages importmap
	$(CONSOLE) importmap:audit

## ── Composer ──────────────────────────────────────────────────────────────

composer-install: ## Installe les dépendances PHP
	$(EXEC) composer install

composer-update: ## Met à jour les dépendances
	$(EXEC) composer update

composer-show: ## Liste les dépendances installées
	$(EXEC) composer show

composer-audit: ## Vérifie les vulnérabilités
	$(EXEC) composer audit

## ── Debug & Cache ─────────────────────────────────────────────────────────

cache-clear: ## Vide le cache
	$(CONSOLE) cache:clear

routes: ## Liste toutes les routes
	$(CONSOLE) debug:router

route: ## Cherche une route précise (usage: make route name=nom_de_la_route)
	$(CONSOLE) debug:router $(name)

container-debug: ## Liste les services disponibles
	$(CONSOLE) debug:container

dotenv: ## Liste les variables d'environnement
	$(CONSOLE) debug:dotenv

doctrine-mapping: ## Affiche la config Doctrine
	$(CONSOLE) doctrine:mapping:info

permissions: ## Corrige les permissions de var/
	$(EXEC) chmod -R 777 var/

## ── Tests ─────────────────────────────────────────────────────────────────

test: ## Lance la suite de tests PHPUnit
	$(EXEC) bin/phpunit
