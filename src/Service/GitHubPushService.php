<?php

namespace App\Service;

use App\Entity\Scan;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Pousse la branche de correction d'un scan vers GitHub et ouvre une pull
 * request. Nécessite un token (`GITHUB_TOKEN`) ayant les droits d'écriture
 * sur le dépôt scanné.
 */
class GitHubPushService
{
    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly LoggerInterface $logger,
        private readonly string $githubToken,
    ) {}

    /** @return array{success: bool, message: string, prUrl: ?string} */
    public function push(Scan $scan): array
    {
        $project     = $scan->getProject();
        $branch      = $scan->getFixBranch();
        $projectPath = $project?->getLocalPath();

        if (!$branch || !$projectPath || !is_dir($projectPath)) {
            return ['success' => false, 'message' => 'Aucune branche de correction à pousser pour ce scan.', 'prUrl' => null];
        }

        if ($this->githubToken === '') {
            return ['success' => false, 'message' => "GITHUB_TOKEN n'est pas configuré côté serveur.", 'prUrl' => null];
        }

        [$owner, $repo] = $this->parseOwnerRepo($project->getRepositoryUrl());
        if (!$owner || !$repo) {
            return ['success' => false, 'message' => "Impossible de déterminer le dépôt GitHub depuis l'URL du projet.", 'prUrl' => null];
        }

        if (!$this->pushBranch($projectPath, $owner, $repo, $branch)) {
            return ['success' => false, 'message' => 'Échec du push vers GitHub (vérifier les droits du token sur ce dépôt).', 'prUrl' => null];
        }

        $prUrl = $this->openPullRequest($owner, $repo, $branch, $scan);

        return [
            'success' => true,
            'message' => $prUrl ? 'Branche poussée et pull request ouverte.' : 'Branche poussée vers GitHub (pull request non créée, voir logs).',
            'prUrl'   => $prUrl,
        ];
    }

    private function pushBranch(string $projectPath, string $owner, string $repo, string $branch): bool
    {
        $remote = "https://x-access-token:{$this->githubToken}@github.com/{$owner}/{$repo}.git";

        $path      = escapeshellarg($projectPath);
        $remoteArg = escapeshellarg($remote);
        $branchArg = escapeshellarg($branch);

        exec("cd {$path} && git -c safe.directory=* push {$remoteArg} {$branchArg}:{$branchArg} 2>&1", $output, $exitCode);

        if ($exitCode !== 0) {
            $this->logger->error('[GitHubPushService] Échec du push de la branche {branch}', [
                'branch' => $branch,
                'output' => implode("\n", $output),
            ]);
        }

        return $exitCode === 0;
    }

    private function openPullRequest(string $owner, string $repo, string $branch, Scan $scan): ?string
    {
        try {
            $base = $this->getDefaultBranch($owner, $repo) ?? 'main';

            $response = $this->httpClient->request('POST', "https://api.github.com/repos/{$owner}/{$repo}/pulls", [
                'auth_bearer' => $this->githubToken,
                'headers'     => [
                    'Accept'     => 'application/vnd.github+json',
                    'User-Agent' => 'SecureScan',
                ],
                'json' => [
                    'title' => "SecureScan — corrections automatiques (scan #{$scan->getId()})",
                    'head'  => $branch,
                    'base'  => $base,
                    'body'  => $this->buildPullRequestBody($scan),
                ],
            ]);

            $data = $response->toArray(false);

            return $data['html_url'] ?? null;
        } catch (\Throwable $e) {
            $this->logger->error('[GitHubPushService] Échec de la création de la pull request : {message}', [
                'message' => $e->getMessage(),
            ]);

            return null;
        }
    }

    private function getDefaultBranch(string $owner, string $repo): ?string
    {
        try {
            $response = $this->httpClient->request('GET', "https://api.github.com/repos/{$owner}/{$repo}", [
                'auth_bearer' => $this->githubToken,
                'headers'     => ['Accept' => 'application/vnd.github+json', 'User-Agent' => 'SecureScan'],
            ]);

            return $response->toArray(false)['default_branch'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }

    private function buildPullRequestBody(Scan $scan): string
    {
        $lines = [];
        foreach ($scan->getFindings() as $finding) {
            if ($finding->getAcceptedFix() === null) {
                continue;
            }
            $lines[] = sprintf('- `%s` : %s (%s)', $finding->getFilePath(), $finding->getTitle(), $finding->getOwaspCategory());
        }

        return "Corrections générées automatiquement par SecureScan pour le scan #{$scan->getId()}.\n\n" . implode("\n", $lines);
    }

    /** @return array{0: ?string, 1: ?string} */
    private function parseOwnerRepo(?string $url): array
    {
        if ($url && preg_match('#github\.com[:/]+([^/]+)/([^/.]+?)(\.git)?/?$#', $url, $m)) {
            return [$m[1], $m[2]];
        }

        return [null, null];
    }
}