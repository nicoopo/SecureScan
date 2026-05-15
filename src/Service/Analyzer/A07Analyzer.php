<?php
namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

class A07Analyzer
{
    private const TOOL = 'securescan';

    private const PATTERNS = [
        [
            'id'          => 'a07.auth.setcookie_no_httponly',
            'regex'       => '/setcookie\s*\([^)]+\)/i',
            'title'       => 'Cookie créé sans flag HttpOnly',
            'description' => 'setcookie() sans le flag HttpOnly expose le cookie aux scripts JavaScript. Ajouter true pour le paramètre httponly.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
            'check'       => 'httponly',
        ],
        [
            'id'          => 'a07.auth.setcookie_no_secure',
            'regex'       => '/setcookie\s*\([^)]+\)/i',
            'title'       => 'Cookie créé sans flag Secure',
            'description' => 'setcookie() sans le flag Secure permet la transmission du cookie en HTTP non chiffré.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
            'check'       => 'secure',
        ],
        [
            'id'          => 'a07.auth.session_no_config',
            'regex'       => '/session_start\s*\(\s*\)/i',
            'title'       => 'session_start() sans configuration sécurisée',
            'description' => "session_start() appelé sans options de sécurité. Utiliser session_start(['cookie_httponly' => true, 'cookie_secure' => true, 'cookie_samesite' => 'Strict']).",
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a07.auth.hardcoded_password',
            'regex'       => '/\$password\s*=\s*[\'"][^\'"]{3,}[\'"]/i',
            'title'       => 'Mot de passe hardcodé pour authentification',
            'description' => "Un mot de passe est écrit en dur dans le code. Utiliser des variables d'environnement.",
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a07.auth.no_session_regenerate',
            'regex'       => '/session_start\s*\(\s*\)/i',
            'title'       => 'Absence de session_regenerate_id() après authentification',
            'description' => 'Après une connexion réussie, session_regenerate_id(true) doit être appelé pour prévenir la fixation de session.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a07.auth.session_gc_maxlifetime',
            'regex'       => '/session\.gc_maxlifetime\s*=\s*0/i',
            'title'       => 'Expiration de session désactivée',
            'description' => "session.gc_maxlifetime=0 désactive l'expiration des sessions. Les sessions ne sont jamais invalidées.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['ini'],
        ],
        [
            'id'          => 'a07.auth.csrf_missing',
            'regex'       => '/<form[^>]*method\s*=\s*["\']post["\'][^>]*>/i',
            'title'       => 'Formulaire POST sans protection CSRF',
            'description' => "Un formulaire POST ne semble pas avoir de token CSRF. Utiliser des tokens CSRF pour protéger les formulaires.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php', 'html', 'twig'],
        ],
        [
            'id'          => 'a07.auth.jwt_no_verify',
            'regex'       => '/jwt_decode\s*\(|JWT::decode\s*\(/i',
            'title'       => 'Décodage JWT sans vérification de signature',
            'description' => 'Un token JWT est décodé sans vérification explicite de la signature. Toujours vérifier la signature avec une clé secrète forte.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php', 'js', 'ts'],
        ],
        [
            'id'          => 'a07.auth.remember_me_insecure',
            'regex'       => '/remember_me|rememberme|remember-me/i',
            'title'       => 'Fonctionnalité remember me potentiellement non sécurisée',
            'description' => "Une fonctionnalité remember me est détectée. Vérifier que les tokens persistants sont hachés en base et ont une expiration.",
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a07.auth.no_brute_force_protection',
            'regex'       => '/SELECT.+WHERE.+password\s*=|checkPassword|verifyPassword/i',
            'title'       => 'Authentification sans protection brute force',
            'description' => "Une vérification de mot de passe est détectée sans limitation de tentatives. Implémenter un rate limiting ou un blocage après N échecs.",
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a07.auth.weak_password_policy',
            'regex'       => '/strlen\s*\(\s*\$password\s*\)\s*[<>]=?\s*[1-5][^0-9]/i',
            'title'       => 'Politique de mot de passe trop faible',
            'description' => 'La longueur minimale du mot de passe semble être inférieure à 8 caractères. Imposer minimum 12 caractères avec complexité.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a07.auth.plain_token_comparison',
            'regex'       => '/\$_(?:GET|POST|REQUEST|COOKIE)\[[\'"]token[\'"]\]\s*==\s*/i',
            'title'       => 'Comparaison de token non sécurisée',
            'description' => "Comparaison de token avec == au lieu de hash_equals(). Vulnérable aux timing attacks.",
            'severity'    => Finding::SEVERITY_HIGH,
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
                    if (!preg_match($pattern['regex'], $lineContent)) continue;

                    if (isset($pattern['check'])) {
                        if ($pattern['check'] === 'httponly' && stripos($lineContent, 'true') !== false) continue;
                        if ($pattern['check'] === 'secure' && stripos($lineContent, 'true') !== false) continue;
                    }

                    $finding = new Finding();
                    $finding
                        ->setScan($scan)
                        ->setTool(self::TOOL)
                        ->setSeverity($pattern['severity'])
                        ->setOwaspCategory(Finding::OWASP_A07)
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
