# SecureScan

Projet Symfony - Guide Git & Docker pour l'équipe

---

## 📥 Cloner le projet

```bash
git clone https://github.com/nicoopo/SecureScan.git
cd SecureScan
```

---

## 🌿 Branches

| Branche | Rôle |
|---|---|
| `main` | Code stable, production |
| `develop` | Branche de travail principale |
| `feature/xxx` | Ta branche personnelle |

---

## 🐳 Lancer le projet avec Docker

### Première fois

```bash
# Copier le fichier d'environnement
cp .env .env.local

# Lancer et build les conteneurs
docker compose up -d --build

# Installer les dépendances PHP
docker exec -it securescan_app composer install

# Créer la base de données
docker exec -it securescan_app php bin/console doctrine:database:create

# Lancer les migrations
docker exec -it securescan_app php bin/console doctrine:migrations:migrate

# Charger les fixtures (données de test)
docker exec -it securescan_app php bin/console doctrine:fixtures:load

# Installer les assets
docker exec -it securescan_app php bin/console asset-map:compile
```

> 🌐 L'application est disponible sur **http://localhost**

---

## 🛠️ Makefile

Un `Makefile` est disponible pour raccourcir les commandes Docker/Symfony du quotidien.

```bash
# Voir toutes les commandes disponibles
make help

# Installation complète (build + composer + BDD + migrations + fixtures + assets)
make install

# Exemples
make up              # Démarrer les conteneurs
make down            # Arrêter les conteneurs
make sh              # Shell dans le conteneur PHP
make migrate         # Lancer les migrations
make fixtures        # Charger les fixtures
make cache-clear     # Vider le cache
make test            # Lancer les tests PHPUnit
```

> Les commandes ci-dessous restent valables si tu préfères ne pas utiliser `make`.

---

## 🐳 Commandes Docker du quotidien

```bash
# Démarrer les conteneurs
docker compose up -d

# Arrêter les conteneurs
docker compose down

# Rebuild après modification du Dockerfile
docker compose up -d --build

# Voir les logs en temps réel
docker compose logs -f

# Voir les logs d'un seul conteneur
docker compose logs -f app
docker compose logs -f db
docker compose logs -f nginx

# Rentrer dans le conteneur PHP
docker exec -it securescan_app bash

# Reset complet (supprime la BDD !)
docker compose down -v
```

---

## ⚙️ Commandes Symfony

> Toutes ces commandes s'exécutent dans le conteneur :
> ```bash
> docker exec -it securescan_app bash
> ```
> Ou en préfixant chaque commande par :
> ```bash
> docker exec -it securescan_app php bin/console ...
> ```

---

### 🗃️ Base de données

```bash
# Créer la base de données
php bin/console doctrine:database:create

# Supprimer la base de données
php bin/console doctrine:database:drop --force

# Créer une migration (après modification d'une entité)
php bin/console make:migration

# Lancer les migrations
php bin/console doctrine:migrations:migrate

# Voir le statut des migrations
php bin/console doctrine:migrations:status

# Charger les fixtures
php bin/console doctrine:fixtures:load

# Valider le schéma
php bin/console doctrine:schema:validate
```

---

### 🏗️ Génération de code

```bash
# Créer une entité
php bin/console make:entity

# Créer un controller
php bin/console make:controller

# Créer un formulaire
php bin/console make:form

# Créer un CRUD complet
php bin/console make:crud

# Créer un voter
php bin/console make:voter

# Créer un event subscriber
php bin/console make:subscriber

# Créer une commande custom
php bin/console make:command

# Créer un test
php bin/console make:test
```

---

### 🎨 Assets (Asset Mapper)

```bash
# Compiler les assets pour la prod
php bin/console asset-map:compile

# Voir la liste des assets mappés
php bin/console debug:asset-map

# Installer un package JS (importmap)
php bin/console importmap:require nom-du-package

# Voir les packages installés
php bin/console importmap:audit
```

---

### 📦 Composer

```bash
# Installer les dépendances
composer install

# Ajouter un package
composer require nom/package

# Ajouter un package de dev uniquement
composer require --dev nom/package

# Mettre à jour les dépendances
composer update

# Voir les dépendances installées
composer show

# Vérifier les vulnérabilités
composer audit
```

---

### 🔧 Debug & Cache

```bash
# Vider le cache
php bin/console cache:clear

# Vider le cache manuellement (si erreur cache)
rm -rf var/cache/*

# Voir toutes les routes
php bin/console debug:router

# Chercher une route précise
php bin/console debug:router nom_de_la_route

# Voir les services disponibles
php bin/console debug:container

# Voir les variables d'environnement
php bin/console debug:dotenv

# Voir la config Doctrine
php bin/console doctrine:mapping:info
```

---

## 🚀 Démarrer une nouvelle feature

```bash
# 1. Se mettre sur develop et récupérer les dernières mises à jour
git checkout develop
git pull origin develop

# 2. Créer ta branche
git checkout -b feature/nom-de-ta-feature

# 3. Travailler...

# 4. Ajouter tes fichiers modifiés
git add .

# 5. Faire un commit
git commit -m "feat: description de ce que tu as fait"

# 6. Pousser ta branche
git push -u origin feature/nom-de-ta-feature
```

---

## 🔄 Mettre à jour sa branche depuis develop

```bash
git checkout develop
git pull origin develop
git checkout feature/nom-de-ta-feature
git merge develop
```

---

## ✅ Fusionner son travail dans develop

1. Va sur GitHub : https://github.com/nicoopo/SecureScan
2. Clique sur **"Compare & pull request"**
3. Base : `develop` ← Compare : `feature/nom-de-ta-feature`
4. Ajoute une description
5. Clique **"Create pull request"**
6. Un collègue relit et valide ✅

---

## 🛠️ Commandes Git du quotidien

```bash
# Voir l'état de tes fichiers
git status

# Voir les branches disponibles
git branch -a

# Changer de branche
git checkout nom-de-la-branche

# Voir l'historique des commits
git log --oneline

# Annuler les modifications d'un fichier (non commité)
git checkout -- nom-du-fichier

# Voir les différences avant de commiter
git diff

# Stash (mettre de côté des modifs sans commiter)
git stash
git stash pop
```

---

## ⚠️ Règles importantes

- ❌ Ne jamais pousser directement sur `main`
- ❌ Ne jamais pousser directement sur `develop`
- ✅ Toujours passer par une branche `feature/`
- ✅ Toujours faire une **Pull Request** pour merger
- ✅ Toujours `git pull` avant de commencer à travailler

---

## 💬 Convention des messages de commit

| Préfixe | Usage |
|---|---|
| `feat:` | Nouvelle fonctionnalité |
| `fix:` | Correction de bug |
| `chore:` | Tâche technique (config, etc.) |
| `style:` | Mise en forme, CSS |
| `docs:` | Documentation |
| `refactor:` | Refactoring de code |
| `test:` | Ajout / modification de tests |

Exemple : `git commit -m "feat: ajout de la page login"`

---

## 🔗 Accès locaux

| Service | URL |
|---|---|
| Application | http://localhost |
| Mailpit (mails) | http://localhost:8025 |
| MySQL | localhost:3306 |

---

## 🏗️ Stack technique

| Outil | Version |
|---|---------|
| PHP | 8.4     |
| Symfony | 8.x     |
| MySQL | 8.0     |
| Nginx | latest  |
| Docker | -       |

---

## 🆘 Problèmes fréquents

### Erreur de cache
```bash
docker exec -it securescan_app rm -rf var/cache/*
docker exec -it securescan_app php bin/console cache:clear
```

### Erreur de permissions
```bash
docker exec -it securescan_app chmod -R 777 var/
```

### Réinitialiser complètement la BDD
```bash
docker exec -it securescan_app php bin/console doctrine:database:drop --force
docker exec -it securescan_app php bin/console doctrine:database:create
docker exec -it securescan_app php bin/console doctrine:migrations:migrate
docker exec -it securescan_app php bin/console doctrine:fixtures:load
```

### Les conteneurs ne démarrent pas
```bash
docker compose down -v
docker compose up -d --build
```
