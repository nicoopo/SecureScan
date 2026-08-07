<?php

namespace App\Service;

use Anthropic\Client;
use Anthropic\Messages\JSONOutputFormat;
use Anthropic\Messages\OutputConfig;
use App\Entity\Finding;
use Psr\Log\LoggerInterface;

/**
 * Génère un fix contextuel via l'API Claude, à partir du code réel du finding
 * (contrairement à FixGeneratorService qui produit un template générique).
 */
class AnthropicFixService
{
    private const MODEL = 'claude-opus-5';

    private const SCHEMA = [
        'type' => 'object',
        'properties' => [
            'proposed_code' => [
                'type' => 'string',
                'description' => "Le code corrigé, prêt à remplacer le code original signalé.",
            ],
            'explanation' => [
                'type' => 'string',
                'description' => "Explication pédagogique en français : pourquoi ce code est vulnérable et pourquoi la correction proposée la résout.",
            ],
        ],
        'required' => ['proposed_code', 'explanation'],
        'additionalProperties' => false,
    ];

    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly string $anthropicApiKey,
    ) {}

    /** @return array{proposedCode: string, explanation: string}|null */
    public function generate(Finding $finding): ?array
    {
        $snippet = $finding->getCodeSnippet();
        if ($this->anthropicApiKey === '' || !$snippet) {
            return null;
        }

        try {
            $client = new Client(apiKey: $this->anthropicApiKey);

            $prompt = sprintf(
                "Tu es un expert en sécurité applicative. Voici une vulnérabilité détectée par une analyse automatisée OWASP Top 10:2025.\n\n"
                . "Catégorie OWASP : %s (%s)\nFichier : %s\nLigne : %s\nTitre : %s\nDescription : %s\n\n"
                . "Code concerné :\n```\n%s\n```\n\n"
                . "Propose une correction précise de CE code exact (pas un template générique) et explique "
                . "pédagogiquement, en français, pourquoi il est vulnérable et pourquoi la correction le résout.",
                $finding->getOwaspCategory(),
                $finding->getOwaspLabel(),
                $finding->getFilePath() ?? '?',
                $finding->getLine() ?? '?',
                $finding->getTitle(),
                $finding->getDescription() ?? '',
                $snippet,
            );

            $message = $client->messages->create(
                model: self::MODEL,
                maxTokens: 2048,
                messages: [['role' => 'user', 'content' => $prompt]],
                outputConfig: OutputConfig::with(format: JSONOutputFormat::with(schema: self::SCHEMA)),
            );

            if ($message->stopReason === 'refusal') {
                $this->logger->warning('[AnthropicFixService] Requête refusée pour le finding #{id}', [
                    'id' => $finding->getId(),
                ]);

                return null;
            }

            $data = json_decode($message->content[0]->text, true);
            if (!isset($data['proposed_code'], $data['explanation'])) {
                return null;
            }

            return [
                'proposedCode' => $data['proposed_code'],
                'explanation'  => $data['explanation'],
            ];
        } catch (\Throwable $e) {
            $this->logger->error('[AnthropicFixService] Échec de la génération IA : {message}', [
                'message' => $e->getMessage(),
            ]);

            return null;
        }
    }
}