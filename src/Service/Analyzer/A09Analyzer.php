<?php

namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

/**
 * Analyseur OWASP A09 - Logging and Monitoring Failures.
 * Détecte : blocs catch vides, error_reporting(0), absence de logger
 * dans les parties critiques du code.
 */
class A09Analyzer
{
    private const TOOL = 'securescan';

    /** Extensions de fichiers inspectées */
    private const EXTENSIONS = ['php', 'js', 'ts'];

    /**
     * Patterns détectés — chaque entrée décrit une règle statique.
     * `extensions` : types de fichiers concernés.
     */
    private const PATTERNS = [
        [
            'id'          => 'a09.logging.empty_catch',
            'regex'       => '/catch\s*\([^)]+\)\s*\{\s*\}/',
            'title'       => 'Bloc catch vide — exception silencieuse',
            'description' => "Un bloc catch vide avale l'exception sans la logger ni la traiter. En cas d'erreur, aucune trace n'est conservée, ce qui rend le diagnostic impossible. Logger l'exception au minimum avec un niveau error ou warning.",
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php', 'js', 'ts'],
        ],
        [
            'id'          => 'a09.logging.catch_no_log',
            'regex'       => '/catch\s*\([^)]+\)\s*\{[^}]*\/\/\s*TODO[^}]*\}/i',
            'title'       => 'Exception capturée avec TODO sans logging',
            'description' => "Un bloc catch contient uniquement un commentaire TODO, sans logging ni traitement réel de l'erreur. Implémenter le logging immédiatement plutôt que de reporter.",
            'severity'    => Finding::SEVERITY_LOW,
            'extensions'  => ['php', 'js', 'ts'],
        ],
        [
            'id'          => 'a09.logging.error_reporting_disabled',
            'regex'       => '/error_reporting\s*\(\s*0\s*\)/i',
            'title'       => 'error_reporting(0) — toutes les erreurs masquées',
            'description' => "error_reporting(0) désactive le rapport d'erreurs PHP. Les erreurs continuent de se produire mais ne sont ni affichées ni loggées. Configurer un niveau approprié et rediriger vers les logs serveur.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a09.logging.at_operator_suppress',
            'regex'       => '/@(?:file_get_contents|fopen|unlink|rename|mkdir|copy|include|require)\s*\(/i',
            'title'       => 'Opérateur @ utilisé pour masquer les erreurs',
            'description' => "L'opérateur @ supprime les erreurs PHP sur l'appel de fonction. Les échecs système (fichier introuvable, permissions, etc.) passent sans trace. Gérer les erreurs explicitement avec un try/catch ou vérifier le retour de la fonction.",
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a09.logging.auth_no_logger',
            'regex'       => '/(?:login|logout|authenticate|checkCredentials|verifyPassword)\s*\([^)]*\)\s*(?::\s*\w+\s*)?\{(?:(?!\$this->logger|\$logger|->log\(|->info\(|->warning\(|->error\().)*?\}/is',
            'title'       => 'Méthode d\'authentification sans logging apparent',
            'description' => "Une méthode liée à l'authentification ne semble contenir aucun appel au logger. Les tentatives de connexion (réussies ou échouées) doivent être tracées pour détecter les attaques par force brute.",
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a09.logging.log_to_dev_null',
            'regex'       => '/(?:error_log|syslog)\s*\([^,)]+,\s*3,\s*[\'"]\/dev\/null[\'"]/i',
            'title'       => 'Logs redirigés vers /dev/null',
            'description' => "Les erreurs sont explicitement redirigées vers /dev/null, ce qui les supprime définitivement. Configurer une destination de log valide (fichier, syslog, service centralisé).",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
    ];

    /**
     * Analyse le code source du projet à la recherche de vulnérabilités A09.
     *
     * @return Finding[]
     */
    public function analyze(Scan $scan, string $projectPath): array
    {
        $findings = [];

        foreach ($this->collectFiles($projectPath) as $filePath) {
            $ext      = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            $relative = $this->relativePath($projectPath, $filePath);

            // Lire le fichier entier pour les patterns multi-lignes
            $content = file_get_contents($filePath);
            $lines   = file($filePath, FILE_IGNORE_NEW_LINES);

            if ($content === false || $lines === false) {
                continue;
            }

            foreach (self::PATTERNS as $pattern) {
                if (!in_array($ext, $pattern['extensions'], true)) {
                    continue;
                }

                // Pattern multi-ligne : chercher dans le contenu complet
                if (isset($pattern['multiline']) && $pattern['multiline']) {
                    if (preg_match($pattern['regex'], $content, $matches, PREG_OFFSET_CAPTURE)) {
                        $lineNum = substr_count(substr($content, 0, $matches[0][1]), "\n") + 1;
                        $findings[] = $this->buildFinding(
                            $scan,
                            $pattern,
                            $relative,
                            $lineNum,
                            trim($lines[$lineNum - 1] ?? '')
                        );
                    }
                    continue;
                }

                // Pattern ligne par ligne
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
            ->setOwaspCategory(Finding::OWASP_A09)
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

            if (!in_array(strtolower($file->getExtension()), self::EXTENSIONS, true)) {
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

    private function relativePath(string $base, string $absolute): string
    {
        return ltrim(substr($absolute, strlen(rtrim($base, '/\\'))), '/\\');
    }
}
