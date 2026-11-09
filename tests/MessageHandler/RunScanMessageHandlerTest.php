<?php

namespace App\Tests\MessageHandler;

use App\Entity\Scan;
use App\Message\RunScanMessage;
use App\MessageHandler\RunScanMessageHandler;
use App\Repository\ScanRepository;
use App\Service\ScanOrchestrator;
use PHPUnit\Framework\TestCase;

class RunScanMessageHandlerTest extends TestCase
{
    public function testRunsOrchestratorOnTheScanFoundByRepository(): void
    {
        $scan = new Scan();

        $repository = $this->createMock(ScanRepository::class);
        $repository->expects($this->once())->method('find')->with(42)->willReturn($scan);

        $orchestrator = $this->createMock(ScanOrchestrator::class);
        $orchestrator->expects($this->once())->method('run')->with($scan);

        $handler = new RunScanMessageHandler($repository, $orchestrator);
        $handler(new RunScanMessage(42));
    }

    public function testDoesNothingWhenScanNoLongerExists(): void
    {
        $repository = $this->createMock(ScanRepository::class);
        $repository->expects($this->once())->method('find')->with(99)->willReturn(null);

        $orchestrator = $this->createMock(ScanOrchestrator::class);
        $orchestrator->expects($this->never())->method('run');

        $handler = new RunScanMessageHandler($repository, $orchestrator);
        $handler(new RunScanMessage(99));
    }
}