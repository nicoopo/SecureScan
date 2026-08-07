# Roadmap SecureScan

Analyse de l'écart entre le code actuel et le `Sujet_Hackathon_SecureScan_2026.pdf`, plus les
pistes d'amélioration notées en session. Mis à jour après lecture du sujet complet.

**Rendu des livrables : jeudi 17h00 (délai impératif). Soutenance : vendredi.**

**État au 07/08 :** points 🔴 1, 3, 4 réglés (PR #39, #40, #41), Semgrep intégré (PR #42),
scan passé en asynchrone via le worker Messenger (PR #43). Reste le point 🔴 2
(intégration Git automatisée) — le plus gros chantier restant — et les livrables non-code.

---

## 🔴 Écarts critiques vs le cahier des charges (points de grille)

### 1. ✅ Aucun vrai outil de sécurité externe n'est orchestré (hors dépendances) — FAIT (PR #39, #42)

Le sujet (§2.1.B) demande d'orchestrer **au minimum 3 outils réels lancés en CLI** parmi
Semgrep, ESLint Security, npm audit, Composer audit, git-secrets, TruffleHog, PHPStan —
avec leur sortie JSON parsée. C'est noté 3 pts ("Architecture & intégration des outils de
sécurité") + fait partie du "Système de correction automatisé" (4 pts) + démo orale
("Démonstration de l'intégration des outils de sécurité", 1 pt).

État initial : `A03Analyzer` appelait de vrais outils CLI (`composer audit`, `npm audit`,
`pip-audit`, `govulncheck`, `bundler-audit`) mais taguait tout `tool = 'securescan'` — le
filtre "outil" du dashboard était mort. `composer audit` était en plus silencieusement
inopérant sans `vendor/` installé (pas de flag `--locked`). Aucun vrai outil SAST n'était
invoqué, seulement des regex PHP maison.

Réglé :
- `A03Analyzer::buildFinding` tague désormais le bon outil réel (`composer_audit`,
  `npm_audit`, `pip_audit`, `govulncheck`, `bundler_audit`) ; `composer audit --locked` audite
  `composer.lock` directement (PR #39).
- `SemgrepAnalyzer` lance `semgrep --config auto --json` en plus des analyseurs regex, mappe
  chaque résultat sur une catégorie OWASP Top 10:2025 via les tags `metadata.owasp` du JSON,
  et tourne à chaque scan aux côtés des analyseurs existants (PR #42).
- Le filtre "outil" du dashboard liste maintenant tous les outils réellement produits.

### 2. Intégration Git automatisée (§2.1.F) — quasi entièrement absente

Notée 4 pts dans la grille technique ("Système de correction automatisé (template-based +
Git)") + 1 pt en soutenance ("Intégration Git API & gestion des branches") + fait partie du
workflow complet démontré à l'oral ("soumission → analyse → résultats → correction → **push**").

Ce qui existe : `Scan::fixBranch` (champ jamais rempli), `FixApplierService` (écrit
directement dans le clone local sur disque, jamais dans une branche Git dédiée).

Ce qui manque entièrement :
- Créer une branche `fix/securescan-{date}` dans le clone local avant d'appliquer les fixes acceptés
- Committer les corrections sur cette branche
- Pusher via l'API GitHub (pas de client Octokit-équivalent en PHP dans le projet, ex.
  `knplabs/github-api` ou simplement `git push` en CLI comme `ProjectCloner` fait déjà `git clone`)
- Idéalement ouvrir une pull request automatiquement

**C'est le plus gros trou du projet par rapport au sujet.** Sans ça, le workflow complet
demandé en livrable #4 et en démo orale n'est pas démontrable de bout en bout.

### 3. ✅ Détection automatique du langage/framework (§2.1.A) — FAIT (PR #40)

`Project::language` (constants `LANGUAGE_PHP`, `LANGUAGE_PYTHON`, etc.) n'était jamais
renseigné. `ProjectCloner::detectLanguage()` détecte maintenant le langage via
`composer.json`/`package.json`/`requirements.txt`/`pyproject.toml`/`go.mod`/`Gemfile`/
`pom.xml`/`build.gradle` à la racine du clone (ajout au passage des constantes
`LANGUAGE_GO`, `LANGUAGE_RUBY`, `LANGUAGE_JAVA`), et `ScanOrchestrator` appelle
`$project->setLanguage(...)` à chaque scan.

### 4. ✅ Rapport PDF incomplet par rapport à l'export HTML — FAIT (PR #41)

`templates/report/pdf.html.twig` n'affichait la section "Corrections appliquées" que si
`scan.fixBranch` était renseigné — ce qui n'arrive jamais (voir point 🔴 2). Le rapport PDF,
livrable #6 explicite du sujet, ne montrait donc jamais les corrections. Un vrai tableau
(fichier / vulnérabilité / OWASP / statut) basé sur `finding.acceptedFix`, identique dans
l'esprit à celui de `export.html.twig`, a été ajouté.

---

## 🟡 Livrables non-code manquants (vérifiés absents du repo)

Aucune trace dans le repo actuel de :
- **Maquettes / wireframes** de l'interface (livrable #2)
- **Diagrammes UML** — cas d'utilisation, classes, activité, séquence (livrable #3)
- **Documentation technique** — installation, config des outils, architecture (livrable #8).
  Le `README.md` actuel ne décrit que les commandes Git/Docker/Symfony du quotidien : il ne
  dit nulle part ce qu'est SecureScan, comment les analyseurs fonctionnent, ni comment
  configurer les outils de sécurité tiers (Semgrep, TruffleHog, etc. une fois intégrés)
- **Présentation PowerPoint** pour la soutenance (livrable #7)

Ces 4 livrables comptent dans la grille technique/orale même s'ils ne sont pas "du code" —
à ne pas laisser pour la dernière heure du jeudi.

---

## 🟢 Ce qui est déjà solide (pas besoin d'y retoucher avant le rendu)

- **Mapping OWASP Top 10:2025** : les 10 catégories sont couvertes avec les libellés exacts
  du sujet (minimum demandé : 5/10) — bien au-delà de l'exigence.
- **Dashboard** : score/grade, répartition par sévérité, distribution OWASP (graphiques),
  liste détaillée avec fichier/ligne/description/sévérité/catégorie, filtres — tout est là,
  filtre "outil" compris (voir point 🔴 1).
- **Système de correction template-based + validation utilisateur** : couvre exactement les
  5 exemples du sujet (SQLi → requêtes préparées, XSS → échappement, dépendances → version
  patchée, secrets → variable d'env, mot de passe clair → bcrypt) avec accept/reject avant
  application. C'est le cœur du §2.1.E, déjà fait.
- **Soumission de projet** : URL Git + upload ZIP, clonage automatique — ok.

---

## 💡 Bonus IA (§2.2 — jusqu'à +3 pts sur la note technique)

Optionnel mais valorisé : appeler une API LLM (Claude, OpenAI, Mistral) avec le
`codeSnippet` réel + le type de vulnérabilité OWASP pour générer un fix contextuel (pas un
template générique), avec explication pédagogique, affiché en diff. `Fix::TYPE_AI` existe
déjà dans l'entité mais n'est jamais produit — c'est littéralement le seul morceau qui
manque pour cette fonctionnalité bonus. À ne considérer qu'une fois les écarts 🔴 réglés.

---

## Autres pistes (notées en session, hors périmètre noté du hackathon)

- **Fixes précis plutôt que génériques** : les analyseurs regex capturent déjà la ligne
  exacte via `preg_match` — on pourrait construire une vraie transformation au lieu d'un
  conseil générique, au moins pour SQLi/XSS/command injection.
- **Dérive des numéros de ligne** : accepter plusieurs fixes sur le même fichier ne réajuste
  pas les `lineStart` des autres findings de ce fichier après insertion.
- **Notifications email** : Mailpit est configuré mais `MailerInterface` n'est utilisé nulle
  part dans `src/`.
- **Export CSV/JSON**, **tendances entre scans**, **partage d'équipe** (un projet = un seul
  owner actuellement) : non demandés par le sujet, à garder pour après le rendu.
- **Tests unitaires** : `tests/` ne contient que `bootstrap.php`. Pas noté explicitement
  dans la grille du hackathon, mais reste le point le plus fragile du projet.
