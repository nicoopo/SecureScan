<?php

namespace App\Controller;

use App\Entity\Scan;
use App\Repository\ScanRepository;
use App\Service\ReportGeneratorService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use App\Service\DashboardChartService;

final class ReportController extends AbstractController
{
    public function __construct(
        private ReportGeneratorService $reportGenerator,
    ) {}

    #[Route('/report', name: 'report_index')]
    public function index(ScanRepository $scanRepository): Response
    {
        $scans = $scanRepository->findBy(['user' => $this->getUser()]);

        return $this->render('report/index.html.twig', [
            'scans' => $scans,
        ]);
    }

    #[Route('/report/{id}', name: 'report_show')]
    public function show(Scan $scan, DashboardChartService $dashboardCharts): Response
    {
        if ($scan->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        return $this->render('report/show.html.twig', [
            'scan'          => $scan,
            'chartSeverity' => $dashboardCharts->buildSeverityChart($scan),
            'chartOwasp'    => $dashboardCharts->buildOwaspChart($scan),
        ]);
    }

    #[Route('/report/{id}/pdf', name: 'report_pdf')]
    public function pdf(Scan $scan): Response
    {
        if ($scan->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        $pdfContent = $this->reportGenerator->generate($scan);
        $filename   = sprintf('report_scan_%d.pdf', $scan->getId());

        return new Response($pdfContent, 200, [
            'Content-Type'        => 'application/pdf',
            'Content-Disposition' => 'attachment; filename="' . $filename . '"',
        ]);
    }
}
