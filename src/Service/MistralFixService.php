<?php

namespace App\Service;

use App\Entity\Finding;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Génère un fix contextuel via l'API Mistral, à partir du code réel du finding
 * (contrairement à FixGeneratorService qui produit un template générique).
 */
class MistralFixService
{
    private const MODEL = 'mistral-small-latest';

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly LoggerInterface $logger,
        private readonly string $mistralApiKey,
    ) {}

    /** @return array{proposedCode: string, explanation: string}|null */
    public function generate(Finding $finding): ?array
    {
        $snippet = $finding->getCodeSnippet();
        if ($this->mistralApiKey === '' || !$snippet) {
            return null;
        }

        $prompt = sprintf(
            "Tu es un expert en sécurité applicative. Voici une vulnérabilité détectée par une analyse automatisée OWASP Top 10:2025.\n\n"
            . "Catégorie OWASP : %s (%s)\nFichier : %s\nLigne : %s\nTitre : %s\nDescription : %s\n\n"
            . "Code concerné :\n```\n%s\n```\n\n"
            . "Propose une correction précise de CE code exact (pas un template générique) et explique "
            . "pédagogiquement, en français, pourquoi il est vulnérable et pourquoi la correction le résout.\n\n"
            . "Réponds uniquement avec un objet JSON contenant exactement ces deux clés : "
            . "\"proposed_code\" (le code corrigé) et \"explanation\" (l'explication en français).",
            $finding->getOwaspCategory(),
            $finding->getOwaspLabel(),
            $finding->getFilePath() ?? '?',
            $finding->getLine() ?? '?',
            $finding->getTitle(),
            $finding->getDescription() ?? '',
            $snippet,
        );

        try {
            $response = $this->httpClient->request('POST', 'https://api.mistral.ai/v1/chat/completions', [
                'auth_bearer' => $this->mistralApiKey,
                'json' => [
                    'model'           => self::MODEL,
                    'messages'        => [['role' => 'user', 'content' => $prompt]],
                    'response_format' => ['type' => 'json_object'],
                ],
            ]);

            $data = $response->toArray(false);

            if ($response->getStatusCode() >= 400) {
                $this->logger->error('[MistralFixService] Échec de la génération IA : {message}', [
                    'message' => $data['message'] ?? $data['error']['message'] ?? 'erreur inconnue',
                ]);

                return null;
            }

            $content = $data['choices'][0]['message']['content'] ?? null;
            if (!$content) {
                return null;
            }

            $parsed = json_decode($content, true);
            if (!isset($parsed['proposed_code'], $parsed['explanation'])) {
                return null;
            }

            return [
                'proposedCode' => $parsed['proposed_code'],
                'explanation'  => $parsed['explanation'],
            ];
        } catch (\Throwable $e) {
            $this->logger->error('[MistralFixService] Échec de la génération IA : {message}', [
                'message' => $e->getMessage(),
            ]);

            return null;
        }
    }
}