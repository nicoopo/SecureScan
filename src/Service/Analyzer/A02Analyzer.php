<?php

namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

/**
 * Analyseur OWASP A02 - Security Misconfiguration.
 * Détecte : mode debug actif, phpinfo(), secrets par défaut, display_errors, etc.
 */
class A02Analyzer
{
    private const TOOL = 'securescan';

    /** Extensions inspectées (les fichiers .env sont gérés séparément via isEnvFile). */
    private const EXTENSIONS = ['php', 'yaml', 'yml', 'xml', 'ini', 'js', 'ts'];

    /**
     * Patterns détectés — chaque entrée décrit une règle statique.
     * `extensions` : types de fichiers concernés ; 'env' cible les fichiers .env*.
     */
    private const PATTERNS = [
        [
            'id'          => 'a02.debug.app_debug_true',
            'regex'       => '/^APP_DEBUG\s*=\s*true\s*$/im',
            'title'       => 'Mode debug Symfony activé (APP_DEBUG=true)',
            'description' => "Le mode debug est activé dans la configuration. En production, cela expose la stack trace complète, les variables d'environnement et la configuration interne. Passer APP_DEBUG=false.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['env'],
        ],
        [
            'id'          => 'a02.debug.phpinfo',
            'regex'       => '/\bphpinfo\s*\(\s*\)/i',
            'title'       => 'Appel phpinfo() détecté',
            'description' => "phpinfo() expose des informations sensibles : version PHP, extensions chargées, chemins système et variables d'environnement. Supprimer de tout code destiné à la production.",
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a02.debug.display_errors_on',
            'regex'       => '/display_errors\s*[=:]\s*[\'"]?\s*(?:On|1|true)\s*[\'"]?/i',
            'title'       => 'Affichage des erreurs PHP activé',
            'description' => "display_errors est activé, ce qui expose les erreurs PHP aux utilisateurs finaux. Désactiver en production (display_errors=Off) et centraliser les erreurs dans les logs serveur.",
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php', 'ini'],
        ],
        [
            'id'          => 'a02.debug.error_reporting_all',
            'regex'       => '/error_reporting\s*\(\s*E_ALL\s*\)/i',
            'title'       => 'error_reporting(E_ALL) potentiellement en production',
            'description' => "E_ALL active tous les niveaux d'erreur PHP. Acceptable uniquement en développement. En production, logger les erreurs côté serveur sans les afficher à l'utilisateur.",
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a02.config.default_app_secret',
            'regex'       => '/APP_SECRET\s*=\s*(?:ThisTokenIsNotSoSecretChangeIt|changeme|secret|your.secret|my.secret)/i',
            'title'       => 'Clé secrète Symfony par défaut non modifiée',
            'description' => "APP_SECRET utilise une valeur connue publiquement. Générer une valeur aléatoire forte (minimum 32 caractères) unique par environnement et ne jamais la committer.",
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['env'],
        ],
        [
            'id'          => 'a02.config.weak_database_password',
            'regex'       => '/:\/\/[^:]+:(?:password|admin|root|changeme|1234|!ChangeMe!)@/i',
            'title'       => 'Mot de passe de base de données faible ou par défaut',
            'description' => "L'URL de connexion à la base de données contient un mot de passe trivial ou par défaut. Utiliser un mot de passe fort unique par environnement.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['env'],
        ],
        [
            'id'          => 'a02.config.expose_php_version',
            'regex'       => '/expose_php\s*=\s*On/i',
            'title'       => 'Version PHP exposée dans les headers HTTP',
            'description' => "expose_php=On révèle la version PHP dans le header X-Powered-By. Désactiver pour ne pas faciliter le ciblage d'exploits spécifiques à une version.",
            'severity'    => Finding::SEVERITY_LOW,
            'extensions'  => ['ini'],
        ],
        [
            'id'          => 'a02.config.hardcoded_credentials',
            'regex'       => '/(?:password|passwd|secret|api_key)\s*=\s*[\'"][^\'"]{3,}[\'"]/i',
            'title'       => 'Identifiant hardcodé dans le code source',
            'description' => "Un mot de passe, secret ou clé d'API semble être écrit en dur dans le code. Utiliser des variables d'environnement et ne jamais committer des secrets dans le dépôt.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php', 'yaml', 'yml'],
        ],
    ];

    /**
     * Analyse le code source du projet à la recherche de vulnérabilités A02.
     *
     * @return Finding[]
     */
    public function analyze(Scan $scan, string $projectPath): array
    {
        $findings = [];

        foreach ($this->collectFiles($projectPath) as $filePath) {
            $ext      = $this->resolveExtension($filePath);
            $relative = $this->relativePath($projectPath, $filePath);
            $lines    = file($filePath, FILE_IGNORE_NEW_LINES);

            if ($lines === false) {
                continue;
            }

            foreach (self::PATTERNS as $pattern) {
                if (!in_array($ext, $pattern['extensions'], true)) {
                    continue;
                }

                foreach ($lines as $index => $lineContent) {
                    if (preg_match($pattern['regex'], $lineContent)) {
                        $findings[] = $this->buildFinding(
                            $scan,
                            $pattern,
                            $relative,
                            $index + 1,
                            trim($lineContent)
                        );
                    }
                }
            }
        }

        return $findings;
    }

    private function buildFinding(Scan $scan, array $pattern, string $filePath, int $line, string $snippet): Finding
    {
        $finding = new Finding();
        $finding
            ->setScan($scan)
            ->setTool(self::TOOL)
            ->setSeverity($pattern['severity'])
            ->setOwaspCategory(Finding::OWASP_A02)
            ->setRuleId($pattern['id'])
            ->setTitle($pattern['title'])
            ->setDescription($pattern['description'])
            ->setFilePath($filePath)
            ->setLine($line)
            ->setCodeSnippet($snippet);

        return $finding;
    }

    /** Parcourt récursivement le répertoire et cède les fichiers analysables. */
    private function collectFiles(string $dir): \Generator
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            /** @var \SplFileInfo $file */
            if (!$file->isFile()) {
                continue;
            }

            $basename  = $file->getBasename();
            $isEnvFile = str_starts_with($basename, '.env');
            $ext       = strtolower($file->getExtension());

            if (!$isEnvFile && !in_array($ext, self::EXTENSIONS, true)) {
                continue;
            }

            // Ignorer les dossiers tiers et le dépôt Git
            $path = $file->getPathname();
            if (str_contains($path, DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR)
                || str_contains($path, DIRECTORY_SEPARATOR . 'node_modules' . DIRECTORY_SEPARATOR)
                || str_contains($path, DIRECTORY_SEPARATOR . '.git' . DIRECTORY_SEPARATOR)
            ) {
                continue;
            }

            yield $path;
        }
    }

    /** Résout l'extension logique d'un fichier (.env* → 'env'). */
    private function resolveExtension(string $filePath): string
    {
        if (str_starts_with(basename($filePath), '.env')) {
            return 'env';
        }

        return strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    }

    private function relativePath(string $base, string $absolute): string
    {
        return ltrim(substr($absolute, strlen(rtrim($base, '/\\'))), '/\\');
    }
}
