<?php

namespace App\Service;

use App\Entity\Scan;
use App\Service\Analyzer\A01Analyzer;
use App\Service\Analyzer\A02Analyzer;
use App\Service\Analyzer\A04Analyzer;
use App\Service\Analyzer\A05Analyzer;
use App\Service\ProjectCloner;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

class ScanOrchestrator
{
    public function __construct(
        private readonly A01Analyzer $a01Analyzer,
        private readonly A02Analyzer $a02Analyzer,
        private  readonly A04Analyzer $a04Analyzer,
        private  readonly A05Analyzer $a05Analyzer,
        private readonly ProjectCloner $cloner,
        private readonly EntityManagerInterface $em,
        private readonly LoggerInterface        $logger,
    ) {}

    public function run(Scan $scan): void
    {
        $projectPath = $scan->getProject()?->getLocalPath();

        if (!$projectPath || !is_dir($projectPath)) {
            $projectPath = $this->cloner->clone($scan->getProject());
            $scan->getProject()->setLocalPath($projectPath);
            $this->em->flush();
        }

        if ($projectPath === null || !is_dir($projectPath)) {
            $scan->fail('Chemin du projet introuvable : ' . ($projectPath ?? 'null'));
            $this->em->flush();

            $this->logger->warning('[ScanOrchestrator] Scan #{id} — répertoire introuvable : {path}', [
                'id'   => $scan->getId(),
                'path' => $projectPath ?? 'null',
            ]);

            return;
        }

        $scan->setStatus(Scan::STATUS_RUNNING);
        $this->em->flush();

        try {
            $findings = [
                ...$this->a01Analyzer->analyze($scan, $projectPath),
                ...$this->a02Analyzer->analyze($scan, $projectPath),
                ...$this->a04Analyzer->analyze($scan, $projectPath),
                ...$this->a05Analyzer->analyze($scan, $projectPath),
            ];

            foreach ($findings as $finding) {
                $scan->addFinding($finding);
                $this->em->persist($finding);
            }

            $scan->finish();

            $this->logger->info('[ScanOrchestrator] Scan #{id} terminé — {count} finding(s) détecté(s).', [
                'id'    => $scan->getId(),
                'count' => count($findings),
            ]);
        } catch (\Throwable $e) {
            $scan->fail($e->getMessage());

            $this->logger->error('[ScanOrchestrator] Erreur lors du scan #{id} : {message}', [
                'id'      => $scan->getId(),
                'message' => $e->getMessage(),
            ]);
        }

        $this->em->flush();
    }
}
