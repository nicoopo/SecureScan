<?php

namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

/**
 * Analyseur OWASP A01 - Broken Access Control.
 * Détecte : CORS trop permissif, IDOR potentiels, escalade de privilèges.
 */
class A01Analyzer
{
    private const TOOL = 'securescan';

    /** Extensions de fichiers inspectées */
    private const EXTENSIONS = ['php', 'yaml', 'yml', 'json', 'js', 'ts'];

    /**
     * Patterns détectés — chaque entrée décrit une règle statique.
     * `extensions` liste les types de fichiers concernés.
     */
    private const PATTERNS = [
        [
            'id'          => 'a01.cors.wildcard_header',
            'regex'       => '/Access-Control-Allow-Origin[\'"\s:]+\*/i',
            'title'       => 'CORS wildcard trop permissif',
            'description' => "Le header Access-Control-Allow-Origin est défini à * ce qui autorise n'importe quelle origine à accéder aux ressources. Restreindre aux domaines de confiance explicitement listés.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php', 'js', 'ts', 'yaml', 'yml'],
        ],
        [
            'id'          => 'a01.cors.allow_all_origins_config',
            'regex'       => '/allowedOrigins[\'"\s:=]+\[?\s*[\'"]?\*[\'"]?\s*\]?/i',
            'title'       => 'Configuration CORS — toutes origines autorisées',
            'description' => "La configuration CORS autorise toutes les origines (*). Définir une liste blanche explicite des domaines autorisés plutôt qu'un wildcard.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php', 'yaml', 'yml', 'json'],
        ],
        [
            'id'          => 'a01.idor.raw_superglobal_in_query',
            'regex'       => '/->(?:find|findBy|findOneBy)\s*\(\s*\$_(?:GET|POST|REQUEST)/i',
            'title'       => 'IDOR potentiel — superglobale utilisée directement en requête',
            'description' => "Un identifiant fourni directement par la superglobale \$_GET/\$_POST/\$_REQUEST est passé sans filtre à une requête Doctrine. Valider l'appartenance de la ressource à l'utilisateur connecté via un Voter.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a01.idor.find_request_param',
            'regex'       => '/->(?:find|findOneBy)\s*\(\s*\$request->(?:get|query->get|request->get)\s*\(/i',
            'title'       => 'IDOR potentiel — paramètre de requête utilisé sans vérification de propriété',
            'description' => "Un identifiant issu de la requête HTTP est passé directement à un find() Doctrine. S'assurer qu'un Voter ou une vérification d'ownership est effectuée avant de retourner la ressource.",
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a01.privilege.commented_access_check',
            'regex'       => '/\/\/\s*(?:\$this->(?:denyAccessUnlessGranted|isGranted)|isGranted\()/i',
            'title'       => 'Vérification de contrôle d\'accès commentée',
            'description' => "Une vérification denyAccessUnlessGranted() ou isGranted() semble avoir été mise en commentaire. Réactiver le contrôle ou documenter explicitement pourquoi il est désactivé.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a01.privilege.hardcoded_admin_bypass',
            'regex'       => '/if\s*\(\s*(?:true|1)\s*\)\s*[\{\/].*(?:admin|ROLE_ADMIN|isAdmin)/i',
            'title'       => 'Contournement de vérification admin hardcodé',
            'description' => "Une condition toujours vraie (if(true) ou if(1)) précède un bloc lié à une vérification de rôle admin. Ce pattern indique un bypass de sécurité potentiellement oublié.",
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
    ];

    /**
     * Analyse le code source du projet à la recherche de vulnérabilités A01.
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
            ->setOwaspCategory(Finding::OWASP_A01)
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
