<?php

namespace App\MessageHandler;

use App\Message\RunScanMessage;
use App\Repository\ScanRepository;
use App\Service\ScanOrchestrator;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

#[AsMessageHandler]
final class RunScanMessageHandler
{
    public function __construct(
        private readonly ScanRepository $scanRepository,
        private readonly ScanOrchestrator $scanOrchestrator,
    ) {}

    public function __invoke(RunScanMessage $message): void
    {
        $scan = $this->scanRepository->find($message->getScanId());

        if ($scan === null) {
            return;
        }

        $this->scanOrchestrator->run($scan);
    }
}