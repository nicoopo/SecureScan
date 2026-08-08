# Roadmap SecureScan

Analyse de l'écart entre le code actuel et le `Sujet_Hackathon_SecureScan_2026.pdf`, plus les
pistes d'amélioration notées en session. Mis à jour après lecture du sujet complet.

**Projet perso, plus de soutenance ni de deadline de hackathon — développé pour le plaisir.**

**État au 07/08 (fin de session) :** les 4 écarts critiques 🔴 sont réglés, Semgrep intégré,
scan asynchrone, intégration Git complète (branche/commit/push/**fork**/PR cross-repo) testée
de bout en bout sur des dépôts réels (y compris un dépôt externe non possédé), et le bonus IA
est fait (Mistral).

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

### 2. ✅ Intégration Git automatisée (§2.1.F) — FAIT (PR #45, #46, #50, #51)

Notée 4 pts dans la grille technique ("Système de correction automatisé (template-based +
Git)") + 1 pt en soutenance ("Intégration Git API & gestion des branches") + fait partie du
workflow complet démontré à l'oral ("soumission → analyse → résultats → correction → **push**").

État initial : `Scan::fixBranch` n'était jamais rempli, `FixApplierService` écrivait
directement dans le clone local sur disque, jamais dans une branche Git dédiée. Aucune
intégration avec l'API GitHub.

Réglé :
- `GitFixWorkflowService` crée/checkout une branche `fix/securescan-{date}` dans le clone
  local dès le premier fix accepté d'un scan, et commit chaque correction appliquée sur
  cette branche.
- `GitHubPushService` pousse la branche vers GitHub (`git push` avec un token embarqué dans
  l'URL du remote, cohérent avec le `git clone` déjà fait par `ProjectCloner`) puis ouvre une
  pull request via l'API REST GitHub.
- Bouton "Pousser vers GitHub" dans le rapport, déclenchement manuel explicite plutôt
  qu'automatique à chaque fix accepté (le push est une action visible côté GitHub, elle
  reste sous contrôle de l'utilisateur).
- Testé de bout en bout sur un vrai dépôt (`nicoopo/symf_demo`) : branche poussée + PR
  ouverte automatiquement.
- **Cas des dépôts publics non possédés** (§ soulevée en session) : si le token n'a pas les
  droits d'écriture sur le dépôt scanné, `GitHubPushService` détecte `permissions.push` via
  l'API GitHub et bascule automatiquement sur un **fork** du compte associé au token, puis
  ouvre une **pull request cross-repo** (fork → dépôt d'origine) — le workflow standard pour
  contribuer à un projet qu'on ne possède pas. Testé de bout en bout sur un dépôt externe réel.
  Limitation GitHub découverte au passage : un token **fine-grained** ne peut pas créer de fork
  via l'API (`Resource not accessible by personal access token`, quels que soient les droits
  accordés) — il faut un **classic token** avec le scope `public_repo` (ou `repo`) pour cette
  action précise. À documenter dans la doc technique du rendu.
- `FixApplierService` excluait les fichiers `.json` (`package.json`, `composer.json`...) de
  toute annotation — bloquant silencieusement tout le flux Git en aval pour les projets dont
  les findings ne portent que sur des manifestes JSON. `applyJsonAnnotation()` insère une clé
  `"// [SecureScan] ..."` (convention répandue, ex. `tsconfig.json`) juste après l'accolade
  ouvrante — reste du JSON valide.
- Au passage : le worker Messenger tournait en `root` (introduit par le passage en async,
  PR #43) alors que PHP-FPM tourne en `www-data` — les projets clonés via un scan async
  devenaient illisibles en écriture pour `FixApplierService` et pour ce nouveau service Git.
  Corrigé en faisant tourner le worker en `www-data` (PR #45).

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

## 🟡 Documentation manquante (vérifiée absente du repo)

- **Documentation technique** — installation, config des outils, architecture.
  Le `README.md` actuel ne décrit que les commandes Git/Docker/Symfony du quotidien : il ne
  dit nulle part ce qu'est SecureScan, comment les analyseurs fonctionnent, ni comment
  configurer les outils de sécurité tiers (Semgrep, TruffleHog, etc. une fois intégrés)

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

## 💡 Bonus IA (§2.2 — jusqu'à +3 pts sur la note technique) — ✅ FAIT (PR #48)

Optionnel mais valorisé : appeler une API LLM avec le `codeSnippet` réel + le type de
vulnérabilité OWASP pour générer un fix contextuel (pas un template générique), avec
explication pédagogique, affiché en diff.

État initial : `Fix::TYPE_AI` existait dans l'entité mais n'était jamais produit.

Réglé :
- `MistralFixService` appelle l'API Mistral (`mistral-small-latest`, `response_format:
  json_object`) avec le code réel du finding + le contexte OWASP, via le `HttpClientInterface`
  de Symfony (pas de nouvelle dépendance HTTP). Sortie structurée `{proposed_code,
  explanation}`.
- Bouton "✨ Générer avec l'IA" dans la modale de fix — régénère le `Fix` pending en place
  (`type=ai`, `proposedCode`, `explanation`), badge "généré par IA" affiché.
- **Anthropic (Claude) essayé en premier** (`AnthropicFixService`, même architecture) mais le
  compte n'avait pas de crédit API — remplacé par Mistral qui a un vrai tier gratuit sans
  carte bancaire, sans changer le contrat côté contrôleur/frontend (juste le service injecté).
- Testé de bout en bout : génère un texte et une correction cohérents sur un finding réel.

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
