<?php
namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

class A03Analyzer
{
    private const TOOL = Finding::TOOL_SECURESCAN;

    private const VULNERABLE_PACKAGES = [
        'phpmailer/phpmailer' => [
            'version' => '6.0.0',
            'title'   => 'PHPMailer version vulnérable',
            'description' => 'PHPMailer < 6.0 contient des vulnérabilités critiques RCE. Mettre à jour vers 6.x minimum.',
            'severity' => Finding::SEVERITY_CRITICAL,
        ],
        'symfony/http-foundation' => [
            'version' => '5.0.0',
            'title'   => 'symfony/http-foundation version obsolète',
            'description' => 'Version ancienne avec des CVE connues. Mettre à jour vers 6.x minimum.',
            'severity' => Finding::SEVERITY_HIGH,
        ],
        'log4php' => [
            'version' => '9999.0.0',
            'title'   => 'log4php déprécié et vulnérable',
            'description' => 'log4php est abandonné et contient des vulnérabilités connues. Utiliser monolog.',
            'severity' => Finding::SEVERITY_HIGH,
        ],
    ];

    public function analyze(Scan $scan, string $projectPath): array
    {
        $findings = [];

        $findings = array_merge($findings, $this->analyzeComposer($scan, $projectPath));
        $findings = array_merge($findings, $this->analyzeNpm($scan, $projectPath));
        $findings = array_merge($findings, $this->analyzePip($scan, $projectPath));
        $findings = array_merge($findings, $this->analyzeGoMod($scan, $projectPath));
        $findings = array_merge($findings, $this->analyzeGemfile($scan, $projectPath));
        $findings = array_merge($findings, $this->analyzeMaven($scan, $projectPath));

        return $findings;
    }

    private function analyzeComposer(Scan $scan, string $projectPath): array
    {
        $findings = [];
        $path = $projectPath . '/composer.json';

        if (!file_exists($path)) return [];

        // Analyse statique des versions
        $data = json_decode(file_get_contents($path), true);
        if ($data) {
            $deps = array_merge($data['require'] ?? [], $data['require-dev'] ?? []);
            foreach ($deps as $package => $version) {
                if (in_array($version, ['*', 'latest', 'dev-master', 'dev-main'], true)) {
                    $findings[] = $this->buildFinding(
                        $scan, 'a03.supply.unfixed_version',
                        "Dépendance sans version fixée : {$package}",
                        "La dépendance {$package} utilise \"{$version}\". Fixer une version précise.",
                        Finding::SEVERITY_MEDIUM, 'composer.json', 1
                    );
                }
                if (isset(self::VULNERABLE_PACKAGES[$package])) {
                    $vuln = self::VULNERABLE_PACKAGES[$package];
                    $findings[] = $this->buildFinding(
                        $scan, 'a03.supply.vulnerable_package',
                        $vuln['title'], $vuln['description'],
                        $vuln['severity'], 'composer.json', 1
                    );
                }
            }
        }

        // Composer audit (--locked : audite composer.lock directement, sans nécessiter `composer install`)
        $output = shell_exec("cd " . escapeshellarg($projectPath) . " && composer audit --locked --format=json 2>/dev/null");
        if ($output) {
            $audit = json_decode($output, true);
            $advisories = $audit['advisories'] ?? [];
            foreach ($advisories as $package => $list) {
                foreach ($list as $advisory) {
                    $findings[] = $this->buildFinding(
                        $scan,
                        'a03.supply.composer_audit.' . ($advisory['cve'] ?? 'unknown'),
                        "[CVE] {$package} : " . ($advisory['title'] ?? 'Vulnérabilité connue'),
                        ($advisory['title'] ?? '') . ' — ' . ($advisory['link'] ?? ''),
                        Finding::SEVERITY_HIGH,
                        'composer.json',
                        1,
                        Finding::TOOL_COMPOSER_AUDIT
                    );
                }
            }
        }

        return $findings;
    }

    private function analyzeNpm(Scan $scan, string $projectPath): array
    {
        $findings = [];
        $path = $projectPath . '/package.json';

        if (!file_exists($path)) return [];

        // Analyse statique
        $data = json_decode(file_get_contents($path), true);
        if ($data) {
            $deps = array_merge($data['dependencies'] ?? [], $data['devDependencies'] ?? []);
            foreach ($deps as $package => $version) {
                if (in_array($version, ['*', 'latest'], true) || str_starts_with($version, 'git+')) {
                    $findings[] = $this->buildFinding(
                        $scan, 'a03.supply.unfixed_version_npm',
                        "Dépendance NPM sans version fixée : {$package}",
                        "La dépendance {$package} utilise \"{$version}\". Fixer une version précise.",
                        Finding::SEVERITY_MEDIUM, 'package.json', 1
                    );
                }
            }
        }

        // npm audit
        $output = shell_exec("cd " . escapeshellarg($projectPath) . " && npm audit --json 2>/dev/null");
        if ($output) {
            $audit = json_decode($output, true);
            $vulns = $audit['vulnerabilities'] ?? [];
            foreach ($vulns as $package => $vuln) {
                $severity = match($vuln['severity'] ?? 'low') {
                    'critical' => Finding::SEVERITY_CRITICAL,
                    'high'     => Finding::SEVERITY_HIGH,
                    'moderate' => Finding::SEVERITY_MEDIUM,
                    default    => Finding::SEVERITY_LOW,
                };
                $findings[] = $this->buildFinding(
                    $scan,
                    'a03.supply.npm_audit.' . $package,
                    "[NPM] {$package} : " . ($vuln['title'] ?? 'Vulnérabilité connue'),
                    "Sévérité : " . ($vuln['severity'] ?? '?') . ". " . ($vuln['url'] ?? ''),
                    $severity,
                    'package.json',
                    1,
                    Finding::TOOL_NPM_AUDIT
                );
            }
        }

        return $findings;
    }

    private function analyzePip(Scan $scan, string $projectPath): array
    {
        $findings = [];
        $path = $projectPath . '/requirements.txt';

        if (!file_exists($path)) return [];

        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        foreach ($lines as $index => $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, '#')) continue;
            if (!preg_match('/^[A-Za-z0-9_.\-\[\]]+==/', $trimmed)) {
                $findings[] = $this->buildFinding(
                    $scan, 'a03.supply.unfixed_version_pip',
                    "Dépendance Python sans version fixée : {$trimmed}",
                    "La dépendance \"{$trimmed}\" n'est pas fixée avec ==. Fixer une version précise pour des builds reproductibles.",
                    Finding::SEVERITY_MEDIUM, 'requirements.txt', $index + 1
                );
            }
        }

        // pip-audit (si installé)
        $output = shell_exec("cd " . escapeshellarg($projectPath) . " && pip-audit -r requirements.txt --format=json 2>/dev/null");
        if ($output) {
            $audit = json_decode($output, true);
            $deps = $audit['dependencies'] ?? $audit ?? [];
            foreach ($deps as $dep) {
                foreach ($dep['vulns'] ?? [] as $vuln) {
                    $findings[] = $this->buildFinding(
                        $scan,
                        'a03.supply.pip_audit.' . ($vuln['id'] ?? 'unknown'),
                        "[pip-audit] " . ($dep['name'] ?? '?') . " : " . ($vuln['id'] ?? 'Vulnérabilité connue'),
                        implode(' ', $vuln['description'] ?? []) ?: 'Voir pip-audit pour les détails.',
                        Finding::SEVERITY_HIGH,
                        'requirements.txt',
                        1,
                        Finding::TOOL_PIP_AUDIT
                    );
                }
            }
        }

        return $findings;
    }

    private function analyzeGoMod(Scan $scan, string $projectPath): array
    {
        $findings = [];
        $modPath = $projectPath . '/go.mod';

        if (!file_exists($modPath)) return [];

        if (!file_exists($projectPath . '/go.sum')) {
            $findings[] = $this->buildFinding(
                $scan, 'a03.supply.go_missing_sum',
                'go.sum absent — checksums des dépendances non vérifiables',
                'Le module Go possède un go.mod mais pas de go.sum. Sans go.sum, les checksums des dépendances ne peuvent pas être vérifiés à l\'installation. Committer go.sum dans le dépôt.',
                Finding::SEVERITY_MEDIUM, 'go.mod', 1
            );
        }

        // govulncheck (si installé)
        $output = shell_exec("cd " . escapeshellarg($projectPath) . " && govulncheck -json ./... 2>/dev/null");
        if ($output) {
            foreach (explode("\n", trim($output)) as $line) {
                $entry = json_decode($line, true);
                $osv = $entry['osv'] ?? null;
                if ($osv) {
                    $findings[] = $this->buildFinding(
                        $scan,
                        'a03.supply.govulncheck.' . ($osv['id'] ?? 'unknown'),
                        "[govulncheck] " . ($osv['id'] ?? 'Vulnérabilité connue'),
                        $osv['summary'] ?? '',
                        Finding::SEVERITY_HIGH,
                        'go.mod',
                        1,
                        Finding::TOOL_GOVULNCHECK
                    );
                }
            }
        }

        return $findings;
    }

    private function analyzeGemfile(Scan $scan, string $projectPath): array
    {
        $findings = [];
        $gemfilePath = $projectPath . '/Gemfile';

        if (!file_exists($gemfilePath)) return [];

        if (!file_exists($projectPath . '/Gemfile.lock')) {
            $findings[] = $this->buildFinding(
                $scan, 'a03.supply.missing_gemfile_lock',
                'Gemfile.lock absent — versions des gems non verrouillées',
                'Un Gemfile existe sans Gemfile.lock. Sans lock file, les versions installées peuvent varier entre environnements. Générer et committer Gemfile.lock.',
                Finding::SEVERITY_MEDIUM, 'Gemfile', 1
            );
        }

        $lines = file($gemfilePath, FILE_IGNORE_NEW_LINES) ?: [];
        foreach ($lines as $index => $line) {
            if (preg_match('/^\s*gem\s+[\'"]([^\'"]+)[\'"]\s*$/', $line, $matches)) {
                $findings[] = $this->buildFinding(
                    $scan, 'a03.supply.unfixed_version_gem',
                    "Dépendance Ruby sans version fixée : {$matches[1]}",
                    "La gem \"{$matches[1]}\" est déclarée sans contrainte de version. Fixer une version précise (ex: gem '{$matches[1]}', '~> 1.2').",
                    Finding::SEVERITY_MEDIUM, 'Gemfile', $index + 1
                );
            }
        }

        // bundler-audit (si installé)
        $output = shell_exec("cd " . escapeshellarg($projectPath) . " && bundler-audit check --format json 2>/dev/null");
        if ($output) {
            $audit = json_decode($output, true);
            foreach ($audit['results'] ?? [] as $result) {
                $advisory = $result['advisory'] ?? [];
                $findings[] = $this->buildFinding(
                    $scan,
                    'a03.supply.bundler_audit.' . ($advisory['id'] ?? 'unknown'),
                    "[bundler-audit] " . ($advisory['title'] ?? 'Vulnérabilité connue'),
                    $advisory['description'] ?? '',
                    Finding::SEVERITY_HIGH,
                    'Gemfile.lock',
                    1,
                    Finding::TOOL_BUNDLER_AUDIT
                );
            }
        }

        return $findings;
    }

    private function analyzeMaven(Scan $scan, string $projectPath): array
    {
        $findings = [];
        $pomPath = $projectPath . '/pom.xml';

        if (!file_exists($pomPath)) return [];

        $lines = file($pomPath, FILE_IGNORE_NEW_LINES) ?: [];
        foreach ($lines as $index => $line) {
            if (preg_match('/<version>\s*(LATEST|RELEASE)\s*<\/version>/i', $line, $matches)) {
                $findings[] = $this->buildFinding(
                    $scan, 'a03.supply.unfixed_version_maven',
                    "Dépendance Maven sans version fixée ({$matches[1]})",
                    "Une dépendance utilise le mot-clé {$matches[1]} au lieu d'une version fixe. Ce comportement est déprécié dans Maven et rend les builds non reproductibles. Fixer une version précise.",
                    Finding::SEVERITY_MEDIUM, 'pom.xml', $index + 1
                );
            }
        }

        return $findings;
    }

    private function buildFinding(Scan $scan, string $ruleId, string $title, string $description, string $severity, string $filePath, int $line, string $tool = self::TOOL): Finding
    {
        $finding = new Finding();
        $finding
            ->setScan($scan)
            ->setTool($tool)
            ->setSeverity($severity)
            ->setOwaspCategory(Finding::OWASP_A03)
            ->setRuleId($ruleId)
            ->setTitle($title)
            ->setDescription($description)
            ->setFilePath($filePath)
            ->setLine($line)
            ->setCodeSnippet('');

        return $finding;
    }
}
