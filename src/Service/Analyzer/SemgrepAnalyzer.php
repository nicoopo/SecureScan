<?php

namespace App\Service\Analyzer;

use App\Entity\Finding;
use App\Entity\Scan;

/**
 * Analyseur SAST basé sur le vrai outil Semgrep (`semgrep --config auto --json`),
 * en complément des analyseurs regex maison.
 */
class SemgrepAnalyzer
{
    private const TOOL = Finding::TOOL_SEMGREP;

    public function analyze(Scan $scan, string $projectPath): array
    {
        $findings = [];

        $output = shell_exec(
            'cd ' . escapeshellarg($projectPath)
            . ' && timeout 120 semgrep --config auto --json --quiet 2>/dev/null'
        );

        if (!$output) {
            return [];
        }

        $data = json_decode($output, true);
        $results = $data['results'] ?? [];

        foreach ($results as $result) {
            $metadata = $result['extra']['metadata'] ?? [];
            $owaspCategory = $this->extractOwaspCategory($metadata);

            if ($owaspCategory === null) {
                continue; // pas de mapping OWASP fiable sur cette règle, on ignore plutôt que de deviner
            }

            $findings[] = $this->buildFinding($scan, $result, $owaspCategory, $projectPath);
        }

        return $findings;
    }

    private function buildFinding(Scan $scan, array $result, string $owaspCategory, string $projectPath): Finding
    {
        $filePath = $result['path'] ?? '';
        $line     = $result['start']['line'] ?? 1;
        $message  = trim($result['extra']['message'] ?? $result['check_id'] ?? 'Vulnérabilité détectée par Semgrep');

        $finding = new Finding();
        $finding
            ->setScan($scan)
            ->setTool(self::TOOL)
            ->setSeverity($this->mapSeverity($result))
            ->setOwaspCategory($owaspCategory)
            ->setRuleId(mb_substr((string) ($result['check_id'] ?? ''), 0, 255))
            ->setTitle(mb_substr($message, 0, 255))
            ->setDescription($message)
            ->setFilePath($filePath)
            ->setLine($line)
            ->setCodeSnippet($this->extractSnippet($projectPath, $filePath, $line))
            ->setRawData($result);

        return $finding;
    }

    /** Lit la ligne concernée directement depuis le fichier : le champ `lines` du JSON Semgrep
     *  affiche "requires login" tant que la CLI n'est pas authentifiée sur semgrep.dev. */
    private function extractSnippet(string $projectPath, string $filePath, int $line): string
    {
        $lines = @file($projectPath . '/' . $filePath, FILE_IGNORE_NEW_LINES);
        if ($lines === false || !isset($lines[$line - 1])) {
            return '';
        }

        return trim($lines[$line - 1]);
    }

    private function mapSeverity(array $result): string
    {
        $extra      = $result['extra'] ?? [];
        $metadata   = $extra['metadata'] ?? [];
        $impact     = strtoupper((string) ($metadata['impact'] ?? ''));
        $likelihood = strtoupper((string) ($metadata['likelihood'] ?? ''));

        if ($impact === 'HIGH' && $likelihood === 'HIGH') {
            return Finding::SEVERITY_CRITICAL;
        }

        return match (strtoupper((string) ($extra['severity'] ?? 'WARNING'))) {
            'ERROR'   => Finding::SEVERITY_HIGH,
            'WARNING' => Finding::SEVERITY_MEDIUM,
            default   => Finding::SEVERITY_LOW,
        };
    }

    /** Priorité au tag OWASP Top 10:2025 (celui utilisé par SecureScan) ; à défaut, retombe sur 2021. */
    private function extractOwaspCategory(array $metadata): ?string
    {
        $owaspTags = $metadata['owasp'] ?? null;
        if (!is_array($owaspTags) || empty($owaspTags)) {
            return null;
        }

        $fallback = null;
        foreach ($owaspTags as $tag) {
            if (preg_match('/^(A\d{2}):(\d{4})/', (string) $tag, $m) && isset(Finding::OWASP_LABELS[$m[1]])) {
                if ($m[2] === '2025') {
                    return $m[1];
                }
                $fallback ??= $m[1];
            }
        }

        return $fallback;
    }
}