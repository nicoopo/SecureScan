<?php
namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

class A05Analyzer
{
    private const TOOL = 'securescan';

    private const PATTERNS = [
        [
            'id'          => 'a05.injection.sql_raw',
            'regex'       => '/\$(?:db|pdo|conn|mysqli|connection)->query\s*\(\s*["\'].*\$|mysqli_query\s*\(.*\$/i',
            'title'       => 'Injection SQL potentielle',
            'description' => 'Une variable est concaténée directement dans une requête SQL. Utiliser des requêtes préparées avec des paramètres liés.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a05.injection.sql_string_concat',
            'regex'       => '/SELECT\s+.+\s+FROM\s+.+\s*["\'\s]*\.\s*\$/i',
            'title'       => 'Concaténation de variable dans requête SQL',
            'description' => 'Une variable PHP est concaténée dans une requête SQL brute. Risque d\'injection SQL. Utiliser PDO avec prepare()/execute().',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a05.injection.xss_echo',
            'regex'       => '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
            'title'       => 'XSS potentiel - variable superglobale affichée sans échappement',
            'description' => 'Une variable superglobale est affichée directement. Utiliser htmlspecialchars() ou htmlentities() avant tout affichage.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a05.injection.command_injection',
            'regex'       => '/\b(?:exec|shell_exec|system|passthru|popen)\s*\(\s*["\']?\s*\$/i',
            'title'       => 'Injection de commande potentielle',
            'description' => 'Une variable est passée directement à une fonction d\'exécution de commande. Utiliser escapeshellarg() et valider les entrées.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a05.injection.eval',
            'regex'       => '/\beval\s*\(\s*\$/i',
            'title'       => 'Utilisation de eval() avec variable',
            'description' => 'eval() avec une variable est extrêmement dangereux et peut mener à une exécution de code arbitraire.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php', 'js', 'ts'],
        ],
        [
            'id'          => 'a05.injection.xss_innerhtml',
            'regex'       => '/\.innerHTML\s*=\s*[^"\'`]/i',
            'title'       => 'XSS potentiel via innerHTML',
            'description' => 'innerHTML avec une variable non échappée peut mener à du XSS. Utiliser textContent ou DOMPurify.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['js', 'ts'],
        ],
    ];

    public function analyze(Scan $scan, string $projectPath): array
    {
        $findings = [];

        foreach ($this->collectFiles($projectPath) as $filePath) {
            $ext      = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            $relative = ltrim(substr($filePath, strlen(rtrim($projectPath, '/\\'))), '/\\');
            $lines    = file($filePath, FILE_IGNORE_NEW_LINES);

            if ($lines === false) continue;

            foreach (self::PATTERNS as $pattern) {
                if (!in_array($ext, $pattern['extensions'], true)) continue;

                foreach ($lines as $index => $lineContent) {
                    if (preg_match($pattern['regex'], $lineContent)) {
                        $finding = new Finding();
                        $finding
                            ->setScan($scan)
                            ->setTool(self::TOOL)
                            ->setSeverity($pattern['severity'])
                            ->setOwaspCategory(Finding::OWASP_A05)
                            ->setRuleId($pattern['id'])
                            ->setTitle($pattern['title'])
                            ->setDescription($pattern['description'])
                            ->setFilePath($relative)
                            ->setLine($index + 1)
                            ->setCodeSnippet(trim($lineContent));
                        $findings[] = $finding;
                    }
                }
            }
        }

        return $findings;
    }

    private function collectFiles(string $dir): \Generator
    {
        if (!is_dir($dir)) return;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            if (!$file->isFile()) continue;
            $path = $file->getPathname();
            if (str_contains($path, '/vendor/') || str_contains($path, '/node_modules/') || str_contains($path, '/.git/')) continue;
            yield $path;
        }
    }
}
