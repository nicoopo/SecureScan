<?php

namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

/**
 * Analyseur OWASP A06 - Insecure Design.
 *
 * Détecte :
 * - uploads non sécurisés,
 * - absence de validation,
 * - routes sensibles sans sécurité,
 * - accès admin sans contrôle,
 * - utilisation directe des paramètres utilisateur.
 */
class A06Analyzer
{
    private const TOOL = 'securescan';

    private const EXTENSIONS = [
        'php',
        'yaml',
        'yml',
        'twig',
        'js',
        'ts',
    ];

    private const PATTERNS = [

        // Upload sans validation
        [
            'id' => 'a06.upload.unvalidated_file_upload',

            'regex' => '/->move\(|move_uploaded_file\(/i',

            'title' => 'Upload de fichier potentiellement non sécurisé',

            'description' => 'Un upload de fichier a été détecté sans validation explicite du type MIME, de la taille ou de l’extension.',

            'severity' => Finding::SEVERITY_HIGH,

            'extensions' => ['php'],
        ],

        // Paramètre utilisateur utilisé directement
        [
            'id' => 'a06.request.direct_input_usage',

            'regex' => '/\$request->get\(/i',

            'title' => 'Utilisation directe d’un paramètre utilisateur',

            'description' => 'Une donnée utilisateur provenant de la requête HTTP est utilisée directement sans validation explicite.',

            'severity' => Finding::SEVERITY_MEDIUM,

            'extensions' => ['php'],
        ],

        // Route sans sécurité
        [
            'id' => 'a06.route.missing_security',

            'regex' => '/#\[Route\(/i',

            'title' => 'Route potentiellement sans contrôle d’accès',

            'description' => 'Une route Symfony a été détectée sans vérification explicite de sécurité.',

            'severity' => Finding::SEVERITY_MEDIUM,

            'extensions' => ['php'],
        ],

        // Zone admin exposée
        [
            'id' => 'a06.admin.missing_role_check',

            'regex' => '/admin/i',

            'title' => 'Zone admin potentiellement non protégée',

            'description' => 'Une fonctionnalité admin a été détectée sans contrôle explicite de rôle.',

            'severity' => Finding::SEVERITY_CRITICAL,

            'extensions' => ['php', 'twig', 'yaml'],
        ],

        // Formulaire sans validation
        [
            'id' => 'a06.form.missing_validation',

            'regex' => '/createForm\(/i',

            'title' => 'Formulaire potentiellement sans validation',

            'description' => 'Un formulaire Symfony est utilisé sans validation explicite détectée.',

            'severity' => Finding::SEVERITY_LOW,

            'extensions' => ['php'],
        ],

        // Sécurité désactivée
        [
            'id' => 'a06.security.disabled',

            'regex' => '/security:\s*false|csrf_protection:\s*false/i',

            'title' => 'Mécanisme de sécurité désactivé',

            'description' => 'Une configuration désactive potentiellement une protection de sécurité importante.',

            'severity' => Finding::SEVERITY_HIGH,

            'extensions' => ['yaml', 'yml'],
        ],
    ];

    /**
     * Analyse le projet.
     *
     * @return Finding[]
     */
    public function analyze(Scan $scan, string $projectPath): array
    {
        $findings = [];

        foreach ($this->collectFiles($projectPath) as $filePath) {

            $extension = strtolower(
                pathinfo($filePath, PATHINFO_EXTENSION)
            );

            $relativePath = $this->relativePath(
                $projectPath,
                $filePath
            );

            $lines = file(
                $filePath,
                FILE_IGNORE_NEW_LINES
            );

            if ($lines === false) {
                continue;
            }

            foreach (self::PATTERNS as $pattern) {

                if (!in_array(
                    $extension,
                    $pattern['extensions'],
                    true
                )) {
                    continue;
                }

                foreach ($lines as $index => $lineContent) {

                    if (preg_match(
                        $pattern['regex'],
                        $lineContent
                    )) {

                        $findings[] = $this->buildFinding(
                            $scan,
                            $pattern,
                            $relativePath,
                            $index + 1,
                            trim($lineContent)
                        );
                    }
                }
            }
        }

        return $findings;
    }

    private function buildFinding(
        Scan $scan,
        array $pattern,
        string $filePath,
        int $line,
        string $snippet
    ): Finding {

        $finding = new Finding();

        $finding
            ->setScan($scan)
            ->setTool(self::TOOL)
            ->setSeverity($pattern['severity'])
            ->setOwaspCategory(Finding::OWASP_A06)
            ->setRuleId($pattern['id'])
            ->setTitle($pattern['title'])
            ->setDescription($pattern['description'])
            ->setFilePath($filePath)
            ->setLine($line)
            ->setCodeSnippet($snippet);

        return $finding;
    }

    /**
     * Parcourt récursivement les fichiers du projet.
     */
    private function collectFiles(string $dir): \Generator
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(
                $dir,
                \RecursiveDirectoryIterator::SKIP_DOTS
            ),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {

            /** @var \SplFileInfo $file */

            if (!$file->isFile()) {
                continue;
            }

            if (!in_array(
                strtolower($file->getExtension()),
                self::EXTENSIONS,
                true
            )) {
                continue;
            }

            $path = $file->getPathname();

            if (
                str_contains($path, DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR)
                || str_contains($path, DIRECTORY_SEPARATOR . 'node_modules' . DIRECTORY_SEPARATOR)
                || str_contains($path, DIRECTORY_SEPARATOR . '.git' . DIRECTORY_SEPARATOR)
            ) {
                continue;
            }

            yield $path;
        }
    }

    private function relativePath(
        string $base,
        string $absolute
    ): string {

        return ltrim(
            substr($absolute, strlen(rtrim($base, '/\\'))),
            '/\\'
        );
    }
}