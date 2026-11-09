<?php

namespace App\Tests\Service;

use App\Entity\Finding;
use App\Service\MistralFixService;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

#[AllowMockObjectsWithoutExpectations]
class MistralFixServiceTest extends TestCase
{
    private LoggerInterface&MockObject $logger;

    protected function setUp(): void
    {
        $this->logger = $this->createMock(LoggerInterface::class);
    }

    public function testReturnsNullAndNeverCallsTheApiWhenApiKeyIsEmpty(): void
    {
        $calls = 0;
        $client = $this->trackingClient($calls, new MockResponse('{}'));
        $service = $this->buildService($client, apiKey: '');

        $result = $service->generate($this->buildFinding());

        $this->assertNull($result);
        $this->assertSame(0, $calls);
    }

    public function testReturnsNullAndNeverCallsTheApiWhenCodeSnippetIsMissing(): void
    {
        $calls = 0;
        $client = $this->trackingClient($calls, new MockResponse('{}'));
        $service = $this->buildService($client);

        $result = $service->generate($this->buildFinding(codeSnippet: null));

        $this->assertNull($result);
        $this->assertSame(0, $calls);
    }

    public function testReturnsProposedCodeAndExplanationOnSuccessAndSendsTheExpectedPayload(): void
    {
        $captured = [];
        $client = new MockHttpClient(function (string $method, string $url, array $options) use (&$captured): MockResponse {
            $captured = ['method' => $method, 'url' => $url, 'options' => $options];

            return new MockResponse(json_encode([
                'choices' => [[
                    'message' => ['content' => json_encode([
                        'proposed_code' => '$stmt = $pdo->prepare(...);',
                        'explanation'   => 'Utiliser une requête préparée.',
                    ])],
                ]],
            ]), ['http_code' => 200]);
        });

        $service = $this->buildService($client, apiKey: 'test-api-key');
        $finding = $this->buildFinding();

        $result = $service->generate($finding);

        $this->assertSame([
            'proposedCode' => '$stmt = $pdo->prepare(...);',
            'explanation'  => 'Utiliser une requête préparée.',
        ], $result);

        $this->assertSame('POST', $captured['method']);
        $this->assertSame('https://api.mistral.ai/v1/chat/completions', $captured['url']);
        // Le client HTTP normalise auth_bearer en header Authorization et json en body JSON brut.
        $this->assertContains('Authorization: Bearer test-api-key', $captured['options']['headers']);
        $body = json_decode($captured['options']['body'], true);
        $this->assertSame('mistral-small-latest', $body['model']);
        $this->assertSame(['type' => 'json_object'], $body['response_format']);

        $prompt = $body['messages'][0]['content'];
        $this->assertStringContainsString(Finding::OWASP_A05, $prompt);
        $this->assertStringContainsString('db.php', $prompt);
        $this->assertStringContainsString('Injection SQL', $prompt);
        $this->assertStringContainsString('$db->query($sql);', $prompt);
    }

    public function testReturnsNullAndLogsWhenApiRespondsWithAnErrorStatus(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse(
            json_encode(['message' => 'Invalid API key']),
            ['http_code' => 401]
        ));
        $service = $this->buildService($client, apiKey: 'bad-key');

        $this->logger->expects($this->once())
            ->method('error')
            ->with($this->anything(), $this->callback(
                static fn (array $context) => $context['message'] === 'Invalid API key'
            ));

        $result = $service->generate($this->buildFinding());

        $this->assertNull($result);
    }

    public function testReturnsNullWhenResponseHasNoMessageContent(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse(
            json_encode(['choices' => []]),
            ['http_code' => 200]
        ));
        $service = $this->buildService($client);

        $this->assertNull($service->generate($this->buildFinding()));
    }

    public function testReturnsNullWhenContentIsNotValidJson(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse(
            json_encode(['choices' => [['message' => ['content' => 'ceci n\'est pas du JSON']]]]),
            ['http_code' => 200]
        ));
        $service = $this->buildService($client);

        $this->assertNull($service->generate($this->buildFinding()));
    }

    public function testReturnsNullWhenContentIsMissingExpectedKeys(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse(
            json_encode(['choices' => [['message' => ['content' => json_encode(['only_this' => 'x'])]]]]),
            ['http_code' => 200]
        ));
        $service = $this->buildService($client);

        $this->assertNull($service->generate($this->buildFinding()));
    }

    public function testReturnsNullAndLogsWhenTheHttpClientFails(): void
    {
        $client = new MockHttpClient(fn () => new MockResponse('', ['error' => 'Connection refused']));
        $service = $this->buildService($client);

        $this->logger->expects($this->once())
            ->method('error')
            ->with($this->anything(), $this->callback(
                static fn (array $context) => str_contains($context['message'], 'Connection refused')
            ));

        $this->assertNull($service->generate($this->buildFinding()));
    }

    private function buildService(MockHttpClient $client, string $apiKey = 'test-api-key'): MistralFixService
    {
        return new MistralFixService($client, $this->logger, $apiKey);
    }

    private function trackingClient(int &$calls, MockResponse $response): MockHttpClient
    {
        return new MockHttpClient(function () use (&$calls, $response): MockResponse {
            $calls++;

            return $response;
        });
    }

    private function buildFinding(?string $codeSnippet = '$db->query($sql);'): Finding
    {
        $finding = new Finding();
        $finding
            ->setTool('securescan')
            ->setSeverity(Finding::SEVERITY_CRITICAL)
            ->setOwaspCategory(Finding::OWASP_A05)
            ->setRuleId('a05.injection.sql_raw')
            ->setTitle('Injection SQL')
            ->setDescription('Description de test.')
            ->setFilePath('db.php')
            ->setLine(12)
            ->setCodeSnippet($codeSnippet);

        return $finding;
    }
}