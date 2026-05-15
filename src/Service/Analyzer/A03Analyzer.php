<?php
namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

class A03Analyzer
{
    private const TOOL = 'securescan';

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

        // Composer audit
        $output = shell_exec("cd " . escapeshellarg($projectPath) . " && composer audit --format=json 2>/dev/null");
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
                        1
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
                    1
                );
            }
        }

        return $findings;
    }

    private function buildFinding(Scan $scan, string $ruleId, string $title, string $description, string $severity, string $filePath, int $line): Finding
    {
        $finding = new Finding();
        $finding
            ->setScan($scan)
            ->setTool(self::TOOL)
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
