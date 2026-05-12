<?php

namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

/**
 * Analyseur OWASP A08 - Software and Data Integrity Failures.
 * Détecte : unserialize() sans vérification, eval() avec données externes,
 * uploads sans vérification d'intégrité.
 */
class A08Analyzer
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
            'id'          => 'a08.integrity.unserialize_user_input',
            'regex'       => '/unserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|data|input|payload|body|content)/i',
            'title'       => 'unserialize() appliqué à des données utilisateur',
            'description' => "unserialize() appelé directement sur une entrée utilisateur permet l'injection d'objets PHP arbitraires (PHP Object Injection). Utiliser json_decode() ou valider l'intégrité de la donnée avant désérialisation.",
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a08.integrity.unserialize_request',
            'regex'       => '/unserialize\s*\(\s*\$request->(?:get|getContent|request->get|query->get)\s*\(/i',
            'title'       => 'unserialize() sur un paramètre de la requête HTTP',
            'description' => "unserialize() est utilisé sur un paramètre HTTP sans validation préalable. Préférer json_decode() et rejeter toute donnée dont l'intégrité ne peut pas être garantie (HMAC, signature).",
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a08.integrity.eval_user_input',
            'regex'       => '/eval\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|data|input|payload|code|expr)/i',
            'title'       => 'eval() exécuté sur des données externes',
            'description' => "eval() avec des données issues de l'utilisateur ou d'une source externe permet l'exécution de code arbitraire. Supprimer eval() et utiliser une alternative sûre adaptée au besoin.",
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a08.integrity.eval_variable',
            'regex'       => '/\beval\s*\(\s*(?!\s*[\'"])[^\)]*\)/i',
            'title'       => 'eval() avec une variable en paramètre',
            'description' => "eval() est appelé avec une variable dont l'origine n'est pas garantie. Tout appel à eval() avec une valeur dynamique est potentiellement dangereux et doit être remplacé.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a08.integrity.move_uploaded_no_check',
            'regex'       => '/move_uploaded_file\s*\([^;]+\)\s*;(?!\s*\/\/.*(?:hash|checksum|integrity|mime|type))/i',
            'title'       => 'Upload de fichier sans vérification d\'intégrité apparente',
            'description' => "move_uploaded_file() est utilisé sans qu'une vérification de type MIME, d'extension ou de hash ne soit visible dans le contexte immédiat. Valider le type réel du fichier (finfo) et son intégrité avant de le déplacer.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a08.integrity.require_remote_url',
            'regex'       => '/(?:require|include)(?:_once)?\s*\(\s*[\'"]https?:\/\//i',
            'title'       => 'Inclusion de fichier depuis une URL distante',
            'description' => "require/include avec une URL distante permet l'exécution de code externe non maîtrisé. Désactiver allow_url_include dans php.ini et toujours inclure des fichiers locaux vérifiés.",
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
    ];

    /**
     * Analyse le code source du projet à la recherche de vulnérabilités A08.
     *
     * @return Finding[]
     */
    public function analyze(Scan $scan, string $projectPath): array
    {
        $findings = [];

        foreach ($this->collectFiles($projectPath) as $filePath) {
            $ext      = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
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
            ->setOwaspCategory(Finding::OWASP_A08)
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
