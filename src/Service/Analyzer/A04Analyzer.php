<?php
namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

class A04Analyzer
{
    private const TOOL = 'securescan';
    private const EXTENSIONS = ['php', 'js', 'ts', 'py'];

    private const PATTERNS = [
        [
            'id'          => 'a04.crypto.md5',
            'regex'       => '/\bmd5\s*\(/i',
            'title'       => 'Algorithme MD5 utilisé',
            'description' => 'MD5 est cryptographiquement cassé. Utiliser SHA-256 minimum ou bcrypt/argon2 pour les mots de passe.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php', 'js', 'ts'],
        ],
        [
            'id'          => 'a04.crypto.sha1',
            'regex'       => '/\bsha1\s*\(/i',
            'title'       => 'Algorithme SHA1 utilisé',
            'description' => 'SHA1 est obsolète et vulnérable aux collisions. Utiliser SHA-256 ou supérieur.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php', 'js', 'ts'],
        ],
        [
            'id'          => 'a04.crypto.plaintext_password',
            'regex'       => '/password\s*=\s*[\'"][^\'"]{3,}[\'"]/i',
            'title'       => 'Mot de passe en clair dans le code',
            'description' => 'Un mot de passe semble être stocké en clair. Utiliser bcrypt ou argon2 pour hacher les mots de passe.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php', 'js', 'ts'],
        ],
        [
            'id'          => 'a04.crypto.base64_password',
            'regex'       => '/base64_encode\s*\(\s*\$password/i',
            'title'       => 'Mot de passe encodé en base64',
            'description' => 'Base64 n\'est pas du chiffrement. Utiliser bcrypt ou argon2.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a04.crypto.weak_random',
            'regex'       => '/\brand\s*\(|mt_rand\s*\(/i',
            'title'       => 'Générateur aléatoire faible utilisé',
            'description' => 'rand() et mt_rand() ne sont pas cryptographiquement sûrs. Utiliser random_bytes() ou random_int().',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
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
                            ->setOwaspCategory(Finding::OWASP_A04)
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
