<?php

namespace App\DataFixtures;


use App\Entity\Finding;
use App\Entity\Scan;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Bundle\FixturesBundle\FixtureGroupInterface;
use Doctrine\Persistence\ObjectManager;

class FindingFixtures extends Fixture implements FixtureGroupInterface
{
    public static function getGroups(): array
    {
        return ['findings'];
    }

    public function load(ObjectManager $manager): void
    {
        $scanRepo = $manager->getRepository(Scan::class);

        // Récupère les scans par leur projet (on prend le premier scan non-failed de chaque projet)
        $scanPhp = $scanRepo->findOneBy(['status' => 'pending']) ?? $scanRepo->findAll()[0];

        // Mieux : on les mappe par index d'insertion
        $scans = $scanRepo->findBy(['status' => 'pending']);

        // Map ref => scan (dans l'ordre d'insertion : php, js, py)
        $scanMap = [
            ScanFixtures::SCAN_PHP_REF => $scans[0] ?? null,
            ScanFixtures::SCAN_JS_REF  => $scans[1] ?? null,
            ScanFixtures::SCAN_PY_REF  => $scans[2] ?? null,
        ];

        foreach ($this->getData() as $data) {
            $scan = $scanMap[$data['scan']] ?? null;

            if (!$scan) {
                throw new \RuntimeException('Scan introuvable pour la ref : ' . $data['scan']);
            }

            $finding = new Finding();
            $finding->setScan($scan);
            $finding->setTool($data['tool']);
            $finding->setSeverity($data['severity']);
            $finding->setOwaspCategory($data['owasp']);
            $finding->setTitle($data['title']);
            $finding->setDescription($data['description'] ?? null);
            $finding->setFilePath($data['file'] ?? null);
            $finding->setLine($data['line'] ?? null);
            $finding->setRuleId($data['ruleId'] ?? null);
            $finding->setCodeSnippet($data['snippet'] ?? null);
            $manager->persist($finding);
        }

        // Finaliser les scans
        foreach ($scanMap as $scan) {
            if ($scan) {
                $scan->finish();
            }
        }

        $manager->flush();
    }

    private function getData(): array
    {
        return [
            // ----------------------------------------------------------------
            // PHP — API Backend
            // ----------------------------------------------------------------
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_CRITICAL,
                'owasp'       => Finding::OWASP_A05,
                'title'       => 'SQL Injection via raw query',
                'description' => 'Requête SQL construite par concaténation sans requêtes préparées.',
                'file'        => 'src/Controller/UserController.php',
                'line'        => 42,
                'ruleId'      => 'php.lang.security.sql-injection',
                'snippet'     => '$db->query("SELECT * FROM users WHERE id = " . $_GET["id"]);',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_CRITICAL,
                'owasp'       => Finding::OWASP_A04,
                'title'       => 'Mot de passe stocké en clair',
                'description' => 'Le mot de passe utilisateur est stocké sans hachage.',
                'file'        => 'src/Service/AuthService.php',
                'line'        => 88,
                'ruleId'      => 'php.lang.security.plaintext-password',
                'snippet'     => '$user->setPassword($_POST["password"]);',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_CRITICAL,
                'owasp'       => Finding::OWASP_A02,
                'title'       => 'Mode debug activé en production',
                'description' => 'APP_DEBUG est à true, ce qui expose les stack traces.',
                'file'        => 'config/packages/security.yaml',
                'line'        => 12,
                'ruleId'      => 'php.symfony.security.debug-enabled',
                'snippet'     => 'APP_DEBUG=true',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_HIGH,
                'owasp'       => Finding::OWASP_A01,
                'title'       => 'Protection CSRF manquante',
                'description' => 'Le formulaire ne vérifie pas le token CSRF.',
                'file'        => 'src/Controller/ApiController.php',
                'line'        => 67,
                'ruleId'      => 'php.symfony.security.missing-csrf',
                'snippet'     => 'public function update(Request $request): Response {',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_TRUFFLEHOG,
                'severity'    => Finding::SEVERITY_HIGH,
                'owasp'       => Finding::OWASP_A04,
                'title'       => 'Clé API hardcodée',
                'description' => 'Une clé API est présente en clair dans le code source.',
                'file'        => 'src/Utils/Mailer.php',
                'line'        => 23,
                'ruleId'      => 'generic.secrets.api-key',
                'snippet'     => '$apiKey = "sk_live_4xZ9...";',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_HIGH,
                'owasp'       => Finding::OWASP_A01,
                'title'       => 'Path traversal vulnerability',
                'description' => 'Chemin construit depuis une entrée utilisateur sans validation.',
                'file'        => 'src/Controller/FileController.php',
                'line'        => 19,
                'ruleId'      => 'php.lang.security.path-traversal',
                'snippet'     => 'file_get_contents("/uploads/" . $_GET["file"]);',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_MEDIUM,
                'owasp'       => Finding::OWASP_A09,
                'title'       => 'Données sensibles dans les logs',
                'description' => 'Des informations sensibles sont loggées en clair.',
                'file'        => 'src/Service/LogService.php',
                'line'        => 7,
                'ruleId'      => 'php.lang.security.sensitive-log',
                'snippet'     => '$logger->info("User password: " . $password);',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_PHPSTAN,
                'severity'    => Finding::SEVERITY_MEDIUM,
                'owasp'       => Finding::OWASP_A06,
                'title'       => 'Validation des entrées manquante',
                'description' => 'Les données du formulaire ne sont pas validées avant traitement.',
                'file'        => 'src/Form/RegisterType.php',
                'line'        => 34,
                'ruleId'      => 'php.symfony.validation.missing-constraints',
                'snippet'     => 'public function buildForm(FormBuilderInterface $builder, array $options): void {',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PHP_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_LOW,
                'owasp'       => Finding::OWASP_A10,
                'title'       => 'Exception non gérée',
                'description' => 'Une exception peut être levée sans être attrapée.',
                'file'        => 'src/Service/ScanService.php',
                'line'        => 55,
                'ruleId'      => 'php.lang.security.unhandled-exception',
                'snippet'     => '$result = json_decode($response, true);',
            ],

            // ----------------------------------------------------------------
            // JavaScript — Frontend App
            // ----------------------------------------------------------------
            [
                'scan'        => ScanFixtures::SCAN_JS_REF,
                'tool'        => Finding::TOOL_ESLINT,
                'severity'    => Finding::SEVERITY_CRITICAL,
                'owasp'       => Finding::OWASP_A05,
                'title'       => 'XSS via innerHTML non échappé',
                'description' => 'Contenu utilisateur injecté dans le DOM sans échappement.',
                'file'        => 'src/components/UserProfile.jsx',
                'line'        => 31,
                'ruleId'      => 'no-inner-html',
                'snippet'     => 'element.innerHTML = user.bio;',
            ],
            [
                'scan'        => ScanFixtures::SCAN_JS_REF,
                'tool'        => Finding::TOOL_NPM_AUDIT,
                'severity'    => Finding::SEVERITY_HIGH,
                'owasp'       => Finding::OWASP_A03,
                'title'       => 'lodash < 4.17.21 (CVE-2021-23337)',
                'description' => 'Version de lodash vulnérable à la prototype pollution.',
                'file'        => 'package.json',
                'line'        => null,
                'ruleId'      => 'CVE-2021-23337',
                'snippet'     => '"lodash": "^4.17.11"',
            ],
            [
                'scan'        => ScanFixtures::SCAN_JS_REF,
                'tool'        => Finding::TOOL_NPM_AUDIT,
                'severity'    => Finding::SEVERITY_HIGH,
                'owasp'       => Finding::OWASP_A03,
                'title'       => 'axios < 1.6.0 (CVE-2023-45857)',
                'description' => 'Version d\'axios exposant des headers CSRF à des tiers.',
                'file'        => 'package.json',
                'line'        => null,
                'ruleId'      => 'CVE-2023-45857',
                'snippet'     => '"axios": "^0.27.2"',
            ],
            [
                'scan'        => ScanFixtures::SCAN_JS_REF,
                'tool'        => Finding::TOOL_TRUFFLEHOG,
                'severity'    => Finding::SEVERITY_HIGH,
                'owasp'       => Finding::OWASP_A04,
                'title'       => 'Token JWT hardcodé',
                'description' => 'Un secret JWT est présent en clair dans le code.',
                'file'        => 'src/config/auth.js',
                'line'        => 8,
                'ruleId'      => 'generic.secrets.jwt-secret',
                'snippet'     => 'const JWT_SECRET = "my_super_secret_key_123";',
            ],
            [
                'scan'        => ScanFixtures::SCAN_JS_REF,
                'tool'        => Finding::TOOL_ESLINT,
                'severity'    => Finding::SEVERITY_MEDIUM,
                'owasp'       => Finding::OWASP_A02,
                'title'       => 'Headers de sécurité manquants',
                'description' => 'L\'application ne définit pas les headers Content-Security-Policy.',
                'file'        => 'server.js',
                'line'        => 15,
                'ruleId'      => 'security/missing-csp',
                'snippet'     => 'app.use(express());',
            ],
            [
                'scan'        => ScanFixtures::SCAN_JS_REF,
                'tool'        => Finding::TOOL_ESLINT,
                'severity'    => Finding::SEVERITY_LOW,
                'owasp'       => Finding::OWASP_A09,
                'title'       => 'Console.log avec données sensibles',
                'description' => 'Des données utilisateur sont affichées dans la console.',
                'file'        => 'src/services/api.js',
                'line'        => 44,
                'ruleId'      => 'no-console',
                'snippet'     => 'console.log("Auth token:", token);',
            ],

            // ----------------------------------------------------------------
            // Python — Data Pipeline
            // ----------------------------------------------------------------
            [
                'scan'        => ScanFixtures::SCAN_PY_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_CRITICAL,
                'owasp'       => Finding::OWASP_A05,
                'title'       => 'Command injection',
                'description' => 'Commande système construite depuis une entrée utilisateur.',
                'file'        => 'app/utils/runner.py',
                'line'        => 18,
                'ruleId'      => 'python.lang.security.command-injection',
                'snippet'     => 'os.system("ping " + user_input)',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PY_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_HIGH,
                'owasp'       => Finding::OWASP_A08,
                'title'       => 'Désérialisation non sécurisée',
                'description' => 'Utilisation de pickle sur des données non fiables.',
                'file'        => 'app/services/cache.py',
                'line'        => 52,
                'ruleId'      => 'python.lang.security.pickle',
                'snippet'     => 'data = pickle.loads(user_data)',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PY_REF,
                'tool'        => Finding::TOOL_TRUFFLEHOG,
                'severity'    => Finding::SEVERITY_HIGH,
                'owasp'       => Finding::OWASP_A04,
                'title'       => 'Clé AWS hardcodée',
                'description' => 'Des credentials AWS sont présents en clair dans le code.',
                'file'        => 'app/config/settings.py',
                'line'        => 9,
                'ruleId'      => 'generic.secrets.aws-key',
                'snippet'     => 'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PY_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_MEDIUM,
                'owasp'       => Finding::OWASP_A07,
                'title'       => 'Absence de limite de tentatives de connexion',
                'description' => 'Aucun mécanisme ne limite les tentatives de connexion.',
                'file'        => 'app/views/auth.py',
                'line'        => 37,
                'ruleId'      => 'python.django.security.no-rate-limit',
                'snippet'     => 'def login(request):',
            ],
            [
                'scan'        => ScanFixtures::SCAN_PY_REF,
                'tool'        => Finding::TOOL_SEMGREP,
                'severity'    => Finding::SEVERITY_LOW,
                'owasp'       => Finding::OWASP_A06,
                'title'       => 'Absence de validation des entrées',
                'description' => 'Les paramètres de la requête ne sont pas validés.',
                'file'        => 'app/views/search.py',
                'line'        => 24,
                'ruleId'      => 'python.django.security.no-input-validation',
                'snippet'     => 'query = request.GET.get("q")',
            ],
        ];
    }

    public function getDependencies(): array
    {
        return [];
    }
}
