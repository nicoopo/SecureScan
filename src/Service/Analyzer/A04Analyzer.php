<?php
namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

class A04Analyzer
{
    private const TOOL = 'securescan';
    private const EXTENSIONS = ['php', 'js', 'ts', 'py', 'java', 'go', 'rb'];

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
            'id'          => 'a04.crypto.md5.python',
            'regex'       => '/hashlib\.md5\s*\(/i',
            'title'       => 'Algorithme MD5 utilisé',
            'description' => 'MD5 est cryptographiquement cassé. Utiliser hashlib.sha256 minimum ou un KDF (bcrypt/argon2) pour les mots de passe.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['py'],
        ],
        [
            'id'          => 'a04.crypto.md5.java',
            'regex'       => '/MessageDigest\.getInstance\s*\(\s*[\'"]MD5[\'"]\s*\)|DigestUtils\.md5(Hex)?\s*\(/i',
            'title'       => 'Algorithme MD5 utilisé',
            'description' => 'MD5 est cryptographiquement cassé. Utiliser SHA-256 minimum ou un KDF (bcrypt/argon2) pour les mots de passe.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['java'],
        ],
        [
            'id'          => 'a04.crypto.md5.go',
            'regex'       => '/\bmd5\.(Sum|New)\s*\(/',
            'title'       => 'Algorithme MD5 utilisé',
            'description' => 'MD5 est cryptographiquement cassé. Utiliser crypto/sha256 minimum ou un KDF (bcrypt/argon2) pour les mots de passe.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['go'],
        ],
        [
            'id'          => 'a04.crypto.md5.ruby',
            'regex'       => '/Digest::MD5/',
            'title'       => 'Algorithme MD5 utilisé',
            'description' => 'MD5 est cryptographiquement cassé. Utiliser Digest::SHA256 minimum ou un KDF (bcrypt/argon2) pour les mots de passe.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['rb'],
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
            'id'          => 'a04.crypto.sha1.python',
            'regex'       => '/hashlib\.sha1\s*\(/i',
            'title'       => 'Algorithme SHA1 utilisé',
            'description' => 'SHA1 est obsolète et vulnérable aux collisions. Utiliser hashlib.sha256 ou supérieur.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['py'],
        ],
        [
            'id'          => 'a04.crypto.sha1.java',
            'regex'       => '/MessageDigest\.getInstance\s*\(\s*[\'"]SHA-?1[\'"]\s*\)|DigestUtils\.sha1(Hex)?\s*\(/i',
            'title'       => 'Algorithme SHA1 utilisé',
            'description' => 'SHA1 est obsolète et vulnérable aux collisions. Utiliser SHA-256 ou supérieur.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['java'],
        ],
        [
            'id'          => 'a04.crypto.sha1.go',
            'regex'       => '/\bsha1\.(Sum|New)\s*\(/',
            'title'       => 'Algorithme SHA1 utilisé',
            'description' => 'SHA1 est obsolète et vulnérable aux collisions. Utiliser crypto/sha256 ou supérieur.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['go'],
        ],
        [
            'id'          => 'a04.crypto.sha1.ruby',
            'regex'       => '/Digest::SHA1/',
            'title'       => 'Algorithme SHA1 utilisé',
            'description' => 'SHA1 est obsolète et vulnérable aux collisions. Utiliser Digest::SHA256 ou supérieur.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['rb'],
        ],
        [
            'id'          => 'a04.crypto.plaintext_password',
            'regex'       => '/password\s*:?=\s*[\'"][^\'"]{3,}[\'"]/i',
            'title'       => 'Mot de passe en clair dans le code',
            'description' => 'Un mot de passe semble être stocké en clair. Utiliser bcrypt ou argon2 pour hacher les mots de passe.',
            'severity'    => Finding::SEVERITY_CRITICAL,
            'extensions'  => ['php', 'js', 'ts', 'py', 'java', 'go', 'rb'],
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
            'id'          => 'a04.crypto.base64_password.python',
            'regex'       => '/base64\.b64encode\s*\(\s*password/i',
            'title'       => 'Mot de passe encodé en base64',
            'description' => 'Base64 n\'est pas du chiffrement. Utiliser bcrypt ou argon2.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['py'],
        ],
        [
            'id'          => 'a04.crypto.base64_password.java',
            'regex'       => '/Base64\.getEncoder\(\)\.encode(ToString)?\s*\(\s*password/i',
            'title'       => 'Mot de passe encodé en base64',
            'description' => 'Base64 n\'est pas du chiffrement. Utiliser bcrypt ou argon2.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['java'],
        ],
        [
            'id'          => 'a04.crypto.base64_password.go',
            'regex'       => '/base64\.\w+\.EncodeToString\s*\(\s*\[\]byte\s*\(\s*password/i',
            'title'       => 'Mot de passe encodé en base64',
            'description' => 'Base64 n\'est pas du chiffrement. Utiliser bcrypt ou argon2.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['go'],
        ],
        [
            'id'          => 'a04.crypto.base64_password.ruby',
            'regex'       => '/Base64\.(strict_)?encode64\s*\(\s*password/i',
            'title'       => 'Mot de passe encodé en base64',
            'description' => 'Base64 n\'est pas du chiffrement. Utiliser bcrypt ou argon2.',
            'severity'    => Finding::SEVERITY_HIGH,
            'extensions'  => ['rb'],
        ],
        [
            'id'          => 'a04.crypto.weak_random',
            'regex'       => '/\brand\s*\(|mt_rand\s*\(/i',
            'title'       => 'Générateur aléatoire faible utilisé',
            'description' => 'rand() et mt_rand() ne sont pas cryptographiquement sûrs. Utiliser random_bytes() ou random_int().',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['php'],
        ],
        [
            'id'          => 'a04.crypto.weak_random.python',
            'regex'       => '/\brandom\.(random|randint|choice|randrange|uniform)\s*\(/i',
            'title'       => 'Générateur aléatoire faible utilisé',
            'description' => 'Le module random n\'est pas cryptographiquement sûr. Utiliser secrets.token_bytes() ou secrets.randbelow().',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['py'],
        ],
        [
            'id'          => 'a04.crypto.weak_random.java',
            'regex'       => '/new\s+Random\s*\(|Math\.random\s*\(/',
            'title'       => 'Générateur aléatoire faible utilisé',
            'description' => 'java.util.Random et Math.random() ne sont pas cryptographiquement sûrs. Utiliser java.security.SecureRandom.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['java'],
        ],
        [
            'id'          => 'a04.crypto.weak_random.go',
            'regex'       => '/"math\/rand"|\brand\.(Intn|Int|Float64)\s*\(/',
            'title'       => 'Générateur aléatoire faible utilisé',
            'description' => 'Le package math/rand n\'est pas cryptographiquement sûr. Utiliser crypto/rand.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['go'],
        ],
        [
            'id'          => 'a04.crypto.weak_random.ruby',
            'regex'       => '/\brand\s*\(|Random\.rand\s*\(|Random\.new\b/',
            'title'       => 'Générateur aléatoire faible utilisé',
            'description' => 'rand et Random ne sont pas cryptographiquement sûrs. Utiliser SecureRandom.',
            'severity'    => Finding::SEVERITY_MEDIUM,
            'extensions'  => ['rb'],
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
