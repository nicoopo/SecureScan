<?php

namespace App\Service;

use App\Entity\Scan;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Pousse la branche de correction d'un scan vers GitHub et ouvre une pull
 * request. Nécessite un token (`GITHUB_TOKEN`) authentifié.
 *
 * Si le token n'a pas les droits d'écriture sur le dépôt scanné (cas d'un
 * dépôt public appartenant à quelqu'un d'autre), la branche est poussée sur
 * un fork du compte associé au token, et la pull request est ouverte en
 * cross-repo (fork → dépôt d'origine) — c'est le workflow GitHub standard
 * pour contribuer à un projet qu'on ne possède pas.
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

        $repoInfo = $this->getRepoInfo($owner, $repo);
        if ($repoInfo === null) {
            return ['success' => false, 'message' => "Impossible d'accéder au dépôt GitHub {$owner}/{$repo}.", 'prUrl' => null];
        }

        $headOwner = $owner;
        $headRepo  = $repo;
        $viaFork   = false;

        if (!$repoInfo['canPush']) {
            $fork = $this->ensureFork($owner, $repo);
            if ($fork === null) {
                return [
                    'success' => false,
                    'message' => "Pas de droit d'écriture sur {$owner}/{$repo} et impossible de le forker (voir logs).",
                    'prUrl'   => null,
                ];
            }
            [$headOwner, $headRepo] = $fork;
            $viaFork = true;
        }

        if (!$this->pushBranch($projectPath, $headOwner, $headRepo, $branch)) {
            return ['success' => false, 'message' => 'Échec du push vers GitHub (vérifier les droits du token sur ce dépôt).', 'prUrl' => null];
        }

        $prUrl = $this->openPullRequest($owner, $repo, $headOwner, $branch, $repoInfo['defaultBranch'], $scan);

        $message = 'Branche poussée vers GitHub (pull request non créée, voir logs).';
        if ($prUrl && $viaFork) {
            $message = "Branche poussée sur votre fork ({$headOwner}/{$headRepo}) et pull request ouverte vers {$owner}/{$repo}.";
        } elseif ($prUrl) {
            $message = 'Branche poussée et pull request ouverte.';
        }

        return ['success' => true, 'message' => $message, 'prUrl' => $prUrl];
    }

    private function pushBranch(string $projectPath, string $owner, string $repo, string $branch): bool
    {
        $remote = "https://x-access-token:{$this->githubToken}@github.com/{$owner}/{$repo}.git";

        $path      = escapeshellarg($projectPath);
        $remoteArg = escapeshellarg($remote);
        $branchArg = escapeshellarg($branch);

        exec("cd {$path} && git -c safe.directory=* push {$remoteArg} {$branchArg}:{$branchArg} 2>&1", $output, $exitCode);

        if ($exitCode !== 0) {
            $this->logger->error('[GitHubPushService] Échec du push de la branche {branch} vers {owner}/{repo}', [
                'branch' => $branch,
                'owner'  => $owner,
                'repo'   => $repo,
                'output' => implode("\n", $output),
            ]);
        }

        return $exitCode === 0;
    }

    /** Crée (ou récupère, si déjà existant) un fork du dépôt sous le compte du token. */
    private function ensureFork(string $owner, string $repo): ?array
    {
        try {
            $response = $this->httpClient->request('POST', "https://api.github.com/repos/{$owner}/{$repo}/forks", [
                'auth_bearer' => $this->githubToken,
                'headers'     => ['Accept' => 'application/vnd.github+json', 'User-Agent' => 'SecureScan'],
            ]);

            $data = $response->toArray(false);

            if ($response->getStatusCode() >= 400) {
                $this->logger->error('[GitHubPushService] Échec de la création du fork de {owner}/{repo} : {message}', [
                    'owner'   => $owner,
                    'repo'    => $repo,
                    'message' => $data['message'] ?? 'réponse inattendue',
                ]);

                return null;
            }

            $forkOwner = $data['owner']['login'] ?? null;
            $forkRepo  = $data['name'] ?? null;
            if (!$forkOwner || !$forkRepo) {
                return null;
            }

            // La création d'un fork est asynchrone côté GitHub : on attend qu'il soit
            // accessible avant d'y pousser (fork déjà existant → réponse immédiate).
            $this->waitUntilReady($forkOwner, $forkRepo);

            return [$forkOwner, $forkRepo];
        } catch (\Throwable $e) {
            $this->logger->error('[GitHubPushService] Échec de la création du fork de {owner}/{repo} : {message}', [
                'owner'   => $owner,
                'repo'    => $repo,
                'message' => $e->getMessage(),
            ]);

            return null;
        }
    }

    private function waitUntilReady(string $owner, string $repo): void
    {
        for ($i = 0; $i < 10; $i++) {
            try {
                $response = $this->httpClient->request('GET', "https://api.github.com/repos/{$owner}/{$repo}", [
                    'auth_bearer' => $this->githubToken,
                    'headers'     => ['Accept' => 'application/vnd.github+json', 'User-Agent' => 'SecureScan'],
                ]);
                if ($response->getStatusCode() === 200) {
                    return;
                }
            } catch (\Throwable) {
                // on retente
            }
            sleep(1);
        }
    }

    private function openPullRequest(string $owner, string $repo, string $headOwner, string $branch, string $base, Scan $scan): ?string
    {
        try {
            $response = $this->httpClient->request('POST', "https://api.github.com/repos/{$owner}/{$repo}/pulls", [
                'auth_bearer' => $this->githubToken,
                'headers'     => [
                    'Accept'     => 'application/vnd.github+json',
                    'User-Agent' => 'SecureScan',
                ],
                'json' => [
                    'title' => "SecureScan — corrections automatiques (scan #{$scan->getId()})",
                    'head'  => "{$headOwner}:{$branch}",
                    'base'  => $base,
                    'body'  => $this->buildPullRequestBody($scan),
                ],
            ]);

            $data = $response->toArray(false);

            if ($response->getStatusCode() === 201) {
                return $data['html_url'] ?? null;
            }

            // 422 "A pull request already exists for {headOwner}:{branch}" — pas une
            // erreur, un fix précédent sur le même scan/branche en a déjà ouvert une.
            $existing = $this->findExistingPullRequest($owner, $repo, $headOwner, $branch);
            if ($existing !== null) {
                return $existing;
            }

            $this->logger->error('[GitHubPushService] Échec de la création de la pull request ({status}) : {message}', [
                'status'  => $response->getStatusCode(),
                'message' => $data['message'] ?? 'réponse inattendue',
            ]);

            return null;
        } catch (\Throwable $e) {
            $this->logger->error('[GitHubPushService] Échec de la création de la pull request : {message}', [
                'message' => $e->getMessage(),
            ]);

            return null;
        }
    }

    private function findExistingPullRequest(string $owner, string $repo, string $headOwner, string $branch): ?string
    {
        try {
            $response = $this->httpClient->request('GET', "https://api.github.com/repos/{$owner}/{$repo}/pulls", [
                'auth_bearer' => $this->githubToken,
                'headers'     => ['Accept' => 'application/vnd.github+json', 'User-Agent' => 'SecureScan'],
                'query'       => ['head' => "{$headOwner}:{$branch}", 'state' => 'open'],
            ]);

            $pulls = $response->toArray(false);

            return $pulls[0]['html_url'] ?? null;
        } catch (\Throwable) {
            return null;
        }
    }

    /** @return array{defaultBranch: string, canPush: bool}|null */
    private function getRepoInfo(string $owner, string $repo): ?array
    {
        try {
            $response = $this->httpClient->request('GET', "https://api.github.com/repos/{$owner}/{$repo}", [
                'auth_bearer' => $this->githubToken,
                'headers'     => ['Accept' => 'application/vnd.github+json', 'User-Agent' => 'SecureScan'],
            ]);

            if ($response->getStatusCode() >= 400) {
                return null;
            }

            $data = $response->toArray(false);

            return [
                'defaultBranch' => $data['default_branch'] ?? 'main',
                'canPush'       => $data['permissions']['push'] ?? false,
            ];
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