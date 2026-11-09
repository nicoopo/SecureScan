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

## 🟡 Documentation — ✅ FAIT

- **Documentation technique** — `README.md` complété avec : présentation du principe de
  bout en bout (soumission → clonage → scan async → analyse → score/rapport → corrections →
  intégration Git), tableau d'architecture (services/contrôleurs/conteneurs Docker), tableau
  des outils de sécurité réellement orchestrés (avec leur tag `Finding::tool`), configuration
  des clés API optionnelles (`MISTRAL_API_KEY`, `GITHUB_TOKEN`) et section tests.
  Au passage, deux inexactitudes corrigées dans le README existant : l'URL de l'app en dev
  était documentée `http://localhost` alors que `compose.yaml` mappe nginx sur `8080:80`
  (donc `http://localhost:8080`) ; et deux limitations honnêtement documentées plutôt que
  passées sous silence — `govulncheck`/`bundler-audit` sont appelés par `A03Analyzer` mais
  **pas installés** dans l'image Docker par défaut (échouent silencieusement, aucun finding
  Go/Ruby), et **TruffleHog** est installé dans l'image (et son tag existe dans `Finding`)
  mais n'est encore branché à aucun analyseur.

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
- **Tests unitaires** — ✅ tous les services du répertoire `src/Service/` sont
  désormais couverts : les 10 analyseurs OWASP (A01-A010),
  `ProjectCloner::detectLanguage`, `FixApplierService`, `FixGeneratorService`,
  `GitFixWorkflowService`, `ChartService`, `ScanOrchestrator`,
  `ReportGeneratorService`, `MistralFixService` et `GitHubPushService`
  (164 tests, `tests/Service/`).
  `GitHubPushServiceTest` mélange deux approches : le `push()` public est testé tel
  quel pour tous les cas qui n'atteignent pas le vrai `git push` réseau (garde-fous,
  échec de récupération des infos du dépôt, échec de création du fork) ; le `git
  push` réel vers github.com est déclenché volontairement en échec **déterministe
  et sans réseau** en pointant `localPath` vers un répertoire qui n'est pas un dépôt
  Git (`git push` échoue instantanément côté client : "fatal: not a git
  repository"). La logique atteignable seulement après un push réussi (ouverture de
  PR, fallback sur une PR existante en cas de 422, construction du corps de la PR)
  est testée directement via Reflection sur les méthodes privées — elles ne font
  que des appels HTTP, entièrement mockables avec `MockHttpClient`.
  `MistralFixServiceTest` utilise `MockHttpClient`/`MockResponse` de Symfony plutôt
  que des mocks PHPUnit manuels — plus réaliste (exerce la vraie normalisation des
  options HTTP : `auth_bearer` devient un header `Authorization`, `json` devient un
  `body` JSON brut). Couvre les deux garde-fous (clé API vide, snippet manquant —
  API jamais appelée), le succès avec vérification du payload envoyé, le statut
  d'erreur HTTP (loggé), la réponse sans contenu, le JSON invalide/incomplet, et
  l'échec de transport (`MockResponse` avec l'option `error`, logué).
  `ReportGeneratorServiceTest` rend le vrai template `report/pdf.html.twig` via un
  `Twig\Environment` autonome (pas besoin du bridge Symfony) et un vrai Dompdf —
  a mis au jour un **bug corrigé au passage** : `generate()` faisait
  `$report->setScan($scan)` mais ne synchronisait jamais le côté inverse
  (`$scan->setReport($report)`). Résultat : rappeler `generate()` deux fois sur le
  même `Scan` en mémoire (sans le refetch depuis la DB) créait un second
  `ScanReport` au lieu de réutiliser l'existant, ce qui aurait violé la contrainte
  unique du `OneToOne` en base à la deuxième sauvegarde. Corrigé avec un simple
  `$scan->setReport($report);`.
  `ScanOrchestratorTest` mocke les 11 analyseurs + cloner + fix generator + EM + logger
  (15 dépendances) : clonage conditionnel du projet, échec propre si le clone reste
  introuvable (aucun analyseur appelé), agrégation des findings de tous les
  analyseurs avec génération/persistance des fixes, et capture d'exception d'un
  analyseur → scan en échec sans rien persister. Les patterns regex se chevauchent
  parfois volontairement (ex. `setcookie()` déclenche à la fois `no_httponly` et
  `no_secure`, `eval($_POST[...])` déclenche à la fois la règle spécifique et la
  règle générique) — verrouillé par des tests dédiés plutôt que corrigé, pour ne pas
  changer le comportement des analyseurs sans décision explicite. Idem pour
  `FixGeneratorService::TEMPLATES` : l'ordre des clés fait foi (`privilege` avant
  `hardcoded_admin_bypass`), verrouillé par un test dédié.
  `GitFixWorkflowServiceTest` est un test d'intégration (vrai dépôt Git temporaire,
  pas de mock de `shell_exec`) — il a mis au jour un vrai bug **corrigé au passage** :
  `checkoutBranch()` utilisait `2>/dev/null`, qui n'existe pas sous Windows. Résultat
  en dev local Windows : la première tentative de checkout échouait toujours, et le
  fallback `checkout -b` refusait de recréer une branche déjà existante — le service
  restait silencieusement sur `main` sans jamais rebasculer sur `fix/securescan-*`.
  Fonctionnait par accident en prod (Docker/Linux, où `/dev/null` existe). Corrigé en
  choisissant le null device selon `DIRECTORY_SEPARATOR` (`NUL` / `/dev/null`).
  `ChartServiceTest` documente au passage que le paramètre `$isDark`, accepté par
  toutes les méthodes publiques, n'est jamais lu dans `create()` : il n'a aujourd'hui
  aucun effet sur les données/options produites (pas corrigé, juste verrouillé par un
  test — peut-être voulu comme point d'extension futur).
- **CI GitHub Actions** — ✅ fait : `.github/workflows/tests.yml` lance PHPUnit sur
  push/PR vers `main`/`develop`. `composer install --no-scripts` pour éviter que les
  auto-scripts Symfony (cache:clear...) tentent de se connecter à la base configurée
  dans `.env` (inutile de toute façon : les tests sont unitaires purs, sans kernel).

---

## 🔵 Tests unitaires hors `src/Service/` — ✅ FAIT à 100%

Les 4 items ci-dessous étaient la dernière poche de code testable en unitaire pur ; c'est fait :

- **`ProjectVoter`** (`src/Security/Voter/`) — ✅ FAIT (`tests/Security/Voter/ProjectVoterTest.php`,
  6 tests) : propriétaire autorisé sur les 4 attributs (VIEW/EDIT/DELETE/SCAN), non-propriétaire
  refusé, token non authentifié (`getUser()` → null) refusé, `UserInterface` étranger (pas une
  `App\Entity\User`) refusé, abstention sur sujet non supporté et sur attribut inconnu. Utilise
  `createStub()` plutôt que `createMock()` pour le `TokenInterface` mocké (PHPUnit 13 émet une
  notice — et `failOnNotice=true` dans `phpunit.dist.xml` — dès qu'un mock sans `expects()` n'est
  pas déclaré comme simple stub).
- **`Scan::computeScore()`** (`src/Entity/Scan.php`) — ✅ FAIT (`tests/Entity/ScanTest.php`,
  12 tests) : aucun finding → 100/A, chaque borne de note testée des deux côtés (89/90,
  74/75, 59/60, 39/40) via un `DataProvider`, plancher à 0 quand les pénalités dépassent 100
  (10 findings critiques), sévérité inconnue sans pénalité (branche `default` du `match`), et
  `finish()` qui bascule bien le statut sur `done` + calcule le score au passage.
- **`SemgrepAnalyzer`** (`src/Service/Analyzer/`) — ✅ FAIT (`tests/Service/Analyzer/SemgrepAnalyzerTest.php`,
  19 tests). `analyze()` shell_exec un vrai binaire `semgrep`, potentiellement absent (ou lent)
  de l'environnement de test — même réserve que pour `A03Analyzer` (composer/npm/pip-audit...).
  La logique propre (parsing du JSON, mapping OWASP, mapping sévérité, lecture du snippet) est
  donc testée directement via Reflection sur les méthodes privées (`buildFinding`, `mapSeverity`,
  `extractOwaspCategory`), même approche que pour la logique de `GitHubPushService` atteignable
  seulement après un vrai appel réseau. Couvre : mapping résultat→Finding, fallback du titre sur
  `check_id` quand `message` est absent, troncature à 255 caractères (titre/ruleId), snippet vide
  si fichier ou ligne introuvable, règle `impact=HIGH && likelihood=HIGH` → critique (prioritaire
  sur le champ `severity`), mapping ERROR/WARNING/INFO/défaut → high/medium/low/medium, priorité
  au tag OWASP 2025 même listé après un tag 2021, catégorie inconnue (hors A01-A10) ignorée avec
  repli sur le tag valide suivant. Seul le garde-fou "pas de sortie" de `analyze()` est testé via
  l'API publique (chemin de projet inexistant → `cd` échoue avant tout appel à `semgrep`).
- **`RunScanMessageHandler`** — ✅ FAIT (`tests/MessageHandler/RunScanMessageHandlerTest.php`,
  2 tests) : scan trouvé → `ScanOrchestrator::run()` appelé avec cette instance ; scan introuvable
  (`find()` renvoie `null`) → l'orchestrateur n'est jamais appelé. `ScanRepository` et
  `ScanOrchestrator` mockés avec `createMock` (pas de vraie DB/dépendances nécessaires).

Plus rien d'identifié à tester en unitaire pur. Hors scope pour des tests unitaires
classiques (nécessiteraient des tests fonctionnels avec kernel Symfony — plus lourd,
pas commencé) :
- Les 7 **contrôleurs** (`src/Controller/`)
- Les **repositories** Doctrine (`src/Repository/`) — s'appuient sur une vraie DB
- Les **formulaires** (`src/Form/`)
