<?php

namespace App\Service;

use App\Entity\Finding;
use App\Entity\Fix;

/**
 * Génère une correction "template" générique pour chaque finding détecté.
 *
 * La correction associe :
 * - l'explication de remédiation déjà rédigée par l'analyseur (Finding::description)
 * - un exemple de code générique correspondant au type de vulnérabilité (ruleId)
 *
 * Ce n'est pas un diff exact du code du projet : c'est un point de départ
 * pédagogique que le développeur adapte, en attendant une génération plus
 * précise (fix IA ou remplacement ligne à ligne).
 */
class FixGeneratorService
{
    /**
     * Snippets génériques indexés par sous-chaîne recherchée dans ruleId.
     * L'ordre compte : la première correspondance (la plus spécifique en tête) l'emporte.
     *
     * @var array<string, string>
     */
    private const TEMPLATES = [
        // A05 — Injection
        'sql_raw' => <<<'CODE'
// Utiliser une requête préparée plutôt que de concaténer la variable
$stmt = $pdo->prepare('SELECT * FROM table WHERE colonne = ?');
$stmt->execute([$valeur]);
CODE,
        'sql_string_concat' => <<<'CODE'
// Utiliser une requête préparée plutôt que de concaténer la variable
$stmt = $pdo->prepare('SELECT * FROM table WHERE colonne = ?');
$stmt->execute([$valeur]);
CODE,
        'sql_string_interp' => <<<'CODE'
// Utiliser une requête paramétrée plutôt qu'une chaîne interpolée
// (execute(query, params) / PreparedStatement / requête paramétrée selon le langage)
CODE,
        'xss_echo' => <<<'CODE'
// Échapper toute donnée utilisateur avant affichage
echo htmlspecialchars($_GET['valeur'], ENT_QUOTES, 'UTF-8');
CODE,
        'xss_innerhtml' => <<<'CODE'
// Préférer textContent, ou nettoyer le HTML avant insertion
element.textContent = valeur;
// ou, si du HTML est réellement nécessaire :
element.innerHTML = DOMPurify.sanitize(valeur);
CODE,
        'command_injection' => <<<'CODE'
// Ne jamais passer une variable brute à une fonction d'exécution shell.
// Échapper l'argument ou, mieux, passer les arguments séparément (pas de shell=True / string unique).
escapeshellarg($valeur);
CODE,
        'eval' => <<<'CODE'
// Éviter eval(). Remplacer par une structure de contrôle explicite,
// une table de correspondance, ou une désérialisation sûre (JSON, etc.).
CODE,

        // A04 — Cryptographie
        'md5' => <<<'CODE'
// Ne pas utiliser MD5 pour un mot de passe. Utiliser un algorithme adapté au hachage de mots de passe.
$hash = password_hash($motDePasse, PASSWORD_BCRYPT);
CODE,
        'sha1' => <<<'CODE'
// Ne pas utiliser SHA1 pour un mot de passe. Utiliser un algorithme adapté au hachage de mots de passe.
$hash = password_hash($motDePasse, PASSWORD_BCRYPT);
CODE,
        'weak_random' => <<<'CODE'
// Utiliser un générateur cryptographiquement sûr plutôt que rand()/mt_rand()
$valeur = random_int($min, $max);
// ou pour des jetons : bin2hex(random_bytes(32));
CODE,
        'base64_password' => <<<'CODE'
// base64 n'est pas du chiffrement. Hacher le mot de passe avec un algorithme dédié.
$hash = password_hash($motDePasse, PASSWORD_BCRYPT);
CODE,
        'plaintext_password' => <<<'CODE'
// Ne jamais stocker un mot de passe en clair
$hash = password_hash($motDePasse, PASSWORD_BCRYPT);
// puis pour vérifier : password_verify($motDePasseSaisi, $hash);
CODE,

        // A01 — Broken Access Control
        'cors' => <<<'CODE'
// Restreindre les origines autorisées, ne jamais utiliser '*' avec des identifiants
header('Access-Control-Allow-Origin: https://mon-domaine-de-confiance.example');
header('Access-Control-Allow-Credentials: true');
CODE,
        'idor' => <<<'CODE'
// Vérifier que la ressource demandée appartient bien à l'utilisateur courant
if ($ressource->getOwner() !== $this->getUser()) {
    throw $this->createAccessDeniedException();
}
CODE,
        'privilege' => <<<'CODE'
// Ne jamais contourner ou commenter une vérification de rôle/permission
$this->denyAccessUnlessGranted('ROLE_ADMIN');
CODE,

        // A02 — Security Misconfiguration
        'debug' => <<<'CODE'
// Désactiver le mode debug et l'affichage des erreurs en production
// .env : APP_ENV=prod, APP_DEBUG=0
// php.ini : display_errors=Off, log_errors=On
CODE,
        'hardcoded_admin_bypass' => <<<'CODE'
// Supprimer tout contournement codé en dur. Utiliser le système de rôles standard.
$this->denyAccessUnlessGranted('ROLE_ADMIN');
CODE,
        'hardcoded_credentials' => <<<'CODE'
// Déplacer le secret dans une variable d'environnement, jamais dans le code source
$apiKey = $_ENV['API_KEY'] ?? throw new \RuntimeException('API_KEY manquante');
CODE,
        'weak_database_password' => <<<'CODE'
// Utiliser un mot de passe fort, généré aléatoirement, stocké en variable d'environnement
DATABASE_URL="mysql://user:$(openssl rand -base64 24)@127.0.0.1:3306/db"
CODE,
        'hardcoded_password' => <<<'CODE'
// Déplacer le mot de passe dans une variable d'environnement, jamais dans le code source
$password = $_ENV['APP_PASSWORD'] ?? throw new \RuntimeException('APP_PASSWORD manquante');
CODE,
        'default_app_secret' => <<<'CODE'
// Générer un secret unique et aléatoire, à ne jamais committer
APP_SECRET=$(openssl rand -hex 32)
CODE,
        'expose_php_version' => <<<'CODE'
// Masquer la version de PHP exposée dans les en-têtes
// php.ini : expose_php = Off
CODE,

        // A07 — Authentication Failures
        'weak_password_policy' => <<<'CODE'
// Exiger une longueur et une complexité minimales
#[Assert\Length(min: 12)]
#[Assert\Regex(pattern: '/[A-Z]/', message: 'Au moins une majuscule')]
private string $password;
CODE,
        'csrf' => <<<'CODE'
// Ajouter un jeton CSRF au formulaire et le vérifier à la soumission
{{ csrf_token('nom_du_formulaire') }}
// côté serveur : $this->isCsrfTokenValid('nom_du_formulaire', $request->request->get('_token'))
CODE,
        'jwt' => <<<'CODE'
// Toujours vérifier la signature du JWT avant de faire confiance à son contenu
$decoded = JWT::decode($token, new Key($clePublique, 'RS256'));
CODE,
        'cookie' => <<<'CODE'
// Ajouter les attributs de sécurité sur les cookies sensibles
setcookie($nom, $valeur, [
    'secure'   => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
CODE,
        'brute_force' => <<<'CODE'
// Limiter le nombre de tentatives (rate limiting / verrouillage temporaire du compte)
$this->rateLimiter->create($identifiant)->consume(1)->ensureAccepted();
CODE,
        'session_regenerate' => <<<'CODE'
// Régénérer l'identifiant de session après authentification pour éviter la fixation de session
session_regenerate_id(true);
CODE,
        'session' => <<<'CODE'
// Configurer explicitement la durée de vie et les attributs sécurisés de la session
ini_set('session.gc_maxlifetime', 1800);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_httponly', 1);
CODE,
        'plain_token_comparison' => <<<'CODE'
// Utiliser une comparaison à temps constant pour éviter les attaques par timing
if (hash_equals($tokenAttendu, $tokenRecu)) { /* ... */ }
CODE,
        'remember_me' => <<<'CODE'
// Générer un jeton aléatoire long, le stocker haché côté serveur
$token = bin2hex(random_bytes(32));
$hash  = hash('sha256', $token);
CODE,

        // A06 — Insecure Design
        'move_uploaded_no_check' => <<<'CODE'
// Vérifier que le fichier provient bien d'un upload HTTP avant de le déplacer
if (is_uploaded_file($tmpName)) {
    move_uploaded_file($tmpName, $destination);
}
CODE,
        'upload' => <<<'CODE'
// Valider l'extension, le type MIME et la taille avant d'accepter un fichier uploadé
if (!in_array($file->guessExtension(), ['jpg', 'png', 'pdf'], true)) {
    throw new \InvalidArgumentException('Type de fichier non autorisé');
}
CODE,
        'missing_role_check' => <<<'CODE'
// Ajouter une vérification de rôle avant l'action d'administration
$this->denyAccessUnlessGranted('ROLE_ADMIN');
CODE,
        'missing_validation' => <<<'CODE'
// Valider les données du formulaire avant de les utiliser
$form->handleRequest($request);
if (!$form->isSubmitted() || !$form->isValid()) {
    return $this->renderForm(...);
}
CODE,
        'missing_security' => <<<'CODE'
// Restreindre l'accès à la route via un contrôle d'accès explicite
#[IsGranted('ROLE_USER')]
CODE,
        'direct_input_usage' => <<<'CODE'
// Ne jamais utiliser une entrée utilisateur directement : valider et filtrer d'abord
$valeur = filter_var($input, FILTER_VALIDATE_INT);
CODE,
        'security.disabled' => <<<'CODE'
// Réactiver le contrôle de sécurité désactivé et couvrir le cas légitime autrement
CODE,

        // A08 — Software/Data Integrity Failures
        'unserialize' => <<<'CODE'
// Ne jamais désérialiser une entrée utilisateur non fiable. Utiliser un format sûr comme JSON.
$data = json_decode($input, true);
CODE,
        'deserialize' => <<<'CODE'
// Ne jamais désérialiser une entrée non fiable sans validation stricte du type attendu.
// Préférer un format sûr comme JSON avec un schéma de validation.
CODE,
        'require_remote_url' => <<<'CODE'
// Ne jamais inclure un fichier depuis une URL distante. Utiliser uniquement des chemins locaux validés.
CODE,

        // A09 / A10 — Logging & Exception Handling
        'empty_catch' => <<<'CODE'
// Ne jamais avaler une exception silencieusement : logger a minima
try {
    // ...
} catch (\Throwable $e) {
    $this->logger->error('Erreur : {message}', ['message' => $e->getMessage()]);
}
CODE,
        'empty_except' => <<<'CODE'
# Ne jamais avaler une exception silencieusement : logger a minima
try:
    ...
except Exception as e:
    logger.error("Erreur : %s", e)
CODE,
        'empty_rescue' => <<<'CODE'
# Ne jamais avaler une exception silencieusement : logger a minima
begin
  ...
rescue => e
  logger.error("Erreur : #{e.message}")
end
CODE,
        'catch_no_log' => <<<'CODE'
// Logger l'exception plutôt que de la traiter silencieusement
catch (\Throwable $e) {
    $this->logger->error('Erreur : {message}', ['message' => $e->getMessage()]);
}
CODE,
        'at_operator_suppress' => <<<'CODE'
// Ne pas supprimer les erreurs avec @. Gérer explicitement le cas d'échec.
if (($resultat = maFonction()) === false) {
    $this->logger->warning('maFonction a échoué');
}
CODE,
        'auth_no_logger' => <<<'CODE'
// Journaliser les événements d'authentification (succès et échecs)
$this->logger->info('Tentative de connexion', ['user' => $login, 'success' => $success]);
CODE,
        'log_to_dev_null' => <<<'CODE'
// Ne pas rediriger les logs vers /dev/null : configurer un vrai handler de logs
monolog:
    handlers:
        main:
            type: stream
            path: "%kernel.logs_dir%/%kernel.environment%.log"
CODE,
        'error_reporting' => <<<'CODE'
// Journaliser les erreurs côté serveur sans les afficher au client
ini_set('display_errors', 'Off');
ini_set('log_errors', 'On');
error_reporting(E_ALL);
CODE,
        'catch_and_continue' => <<<'CODE'
// Ne pas poursuivre le traitement après une erreur non gérée : logger et interrompre proprement
catch (\Throwable $e) {
    $this->logger->error($e->getMessage());
    throw $e;
}
CODE,
        'die_with_message' => <<<'CODE'
// Ne pas exposer de détail technique au client : logger côté serveur, message générique côté client
$this->logger->error($e->getMessage());
throw new \RuntimeException('Une erreur est survenue');
CODE,
        'expose_trace' => <<<'CODE'
// Ne jamais renvoyer la stack trace au client : logger côté serveur uniquement
$this->logger->error($e->getMessage(), ['trace' => $e->getTraceAsString()]);
return new Response('Une erreur est survenue', 500);
CODE,
        'expose_message' => <<<'CODE'
// Ne pas renvoyer le message d'exception brut au client
$this->logger->error($e->getMessage());
return new Response('Une erreur est survenue', 500);
CODE,
        'var_dump_exception' => <<<'CODE'
// Retirer le var_dump()/print_r() de debug : logger l'exception à la place
$this->logger->error($e->getMessage(), ['exception' => $e]);
CODE,
        'generic_exception' => <<<'CODE'
// Attraper des exceptions typées plutôt qu'une exception générique
catch (\InvalidArgumentException $e) {
    // traitement spécifique
}
CODE,

        // A03 — Software Supply Chain
        'unfixed_version' => <<<'CODE'
// Fixer une version précise plutôt qu'un caractère générique
"paquet": "^2.4.1"
CODE,
        'vulnerable_package' => <<<'CODE'
// Mettre à jour vers la version corrigée du paquet
composer require paquet:^X.Y.Z
CODE,
        'composer_audit' => <<<'CODE'
// Mettre à jour la dépendance vers la version corrigée indiquée par l'avis de sécurité
composer update paquet
CODE,
        'npm_audit' => <<<'CODE'
// Mettre à jour la dépendance vers la version corrigée
npm audit fix
CODE,
        'pip_audit' => <<<'CODE'
# Mettre à jour la dépendance vers la version corrigée
pip install --upgrade paquet
CODE,
        'govulncheck' => <<<'CODE'
// Mettre à jour le module vers la version corrigée
go get -u module@version
CODE,
        'bundler_audit' => <<<'CODE'
# Mettre à jour la gem vers la version corrigée
bundle update gem
CODE,
        'missing_sum' => <<<'CODE'
// Générer et committer go.sum pour vérifier les checksums des dépendances
go mod tidy
CODE,
        'missing_gemfile_lock' => <<<'CODE'
# Générer et committer Gemfile.lock pour verrouiller les versions des gems
bundle install
CODE,
    ];

    public function generate(Finding $finding): Fix
    {
        $fix = new Fix();
        $fix->setType(Fix::TYPE_TEMPLATE)
            ->setStatus(Fix::STATUS_PENDING)
            ->setOriginalCode($finding->getCodeSnippet())
            ->setProposedCode($this->resolveProposedCode($finding))
            ->setExplanation($finding->getDescription() ?? $finding->getTitle())
            ->setFilePath($finding->getFilePath())
            ->setLineStart($finding->getLine())
            ->setLineEnd($finding->getLine());

        $finding->addFix($fix);

        return $fix;
    }

    private function resolveProposedCode(Finding $finding): string
    {
        $ruleId = strtolower($finding->getRuleId() ?? '');

        if ($ruleId !== '') {
            foreach (self::TEMPLATES as $needle => $code) {
                if (str_contains($ruleId, $needle)) {
                    return $code;
                }
            }
        }

        return $this->genericFallback($finding);
    }

    private function genericFallback(Finding $finding): string
    {
        $label = $finding->getOwaspLabel();

        return "// Corriger selon la recommandation OWASP {$finding->getOwaspCategory()} ({$label}) :\n"
            . "// " . ($finding->getDescription() ?? $finding->getTitle());
    }
}
