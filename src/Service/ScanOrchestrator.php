<?php

namespace App\Service;

use App\Entity\Scan;
use App\Service\Analyzer\A01Analyzer;
use App\Service\Analyzer\A02Analyzer;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * Orchestrateur de scan — coordonne les analyseurs OWASP et finalise le Scan.
 *
 * Injecter ce service dans un Controller ou une Command pour lancer un scan :
 *   $this->scanOrchestrator->run($scan);
 */
class ScanOrchestrator
{
    public function __construct(
        private readonly A01Analyzer            $a01Analyzer,
        private readonly A02Analyzer            $a02Analyzer,
        private readonly EntityManagerInterface $em,
        private readonly LoggerInterface        $logger,
    ) {}

    /**
     * Exécute tous les analyseurs sur le projet lié au scan.
     * Met à jour le statut, persiste les findings et calcule le score final.
     */
    public function run(Scan $scan): void
    {
        $projectPath = $scan->getProject()?->getLocalPath();

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
