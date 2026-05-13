<?php

namespace App\Controller;

use App\Entity\Scan;
use App\Repository\ScanRepository;
use App\Service\ChartService;
use App\Service\ReportGeneratorService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final class ReportController extends AbstractController
{
    public function __construct(
        private ReportGeneratorService $reportGenerator,
        private ChartService $chartService,
    ) {}

    #[Route('/report', name: 'report_index')]
    public function index(ScanRepository $scanRepository): Response
    {
        $scans = $scanRepository->findByUser($this->getUser());

        return $this->render('report/index.html.twig', [
            'scans' => $scans,
        ]);
    }

    #[Route('/report/{id}', name: 'report_show')]
    public function show(Scan $scan, Request $request): Response
    {
        if ($scan->getProject()->getOwner() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        $filters = [
            'severity' => $request->query->get('severity'),
            'owasp'    => $request->query->get('owasp'),
            'tool'     => $request->query->get('tool'),
        ];

        return $this->render('report/show.html.twig', [
            'scan'          => $scan,
            'chartSeverity' => $this->chartService->buildSeverityChart($scan),
            'chartOwasp'    => $this->chartService->buildOwaspChart($scan),
            'filters'       => $filters,
        ]);
    }

    #[Route('/report/{id}/pdf', name: 'report_pdf')]
    public function pdf(Scan $scan): Response
    {
        if ($scan->getProject()->getOwner() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        $pdfContent = $this->reportGenerator->generate($scan);
        $filename   = sprintf('report_scan_%d.pdf', $scan->getId());

        return new Response($pdfContent, 200, [
            'Content-Type'        => 'application/pdf',
            'Content-Disposition' => 'attachment; filename="' . $filename . '"',
        ]);
    }

    #[Route('/report/{id}/html', name: 'report_html')]
    public function html(Scan $scan): Response
    {
        if ($scan->getProject()->getOwner() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        $findings = $scan->getFindings()->toArray();
        usort($findings, function($a, $b) {
            $order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
            return ($order[$a->getSeverity()] ?? 99) <=> ($order[$b->getSeverity()] ?? 99);
        });

        return $this->render('report/export.html.twig', [
            'scan'     => $scan,
            'findings' => $findings,
        ]);
    }

    #[Route('/report/{token}/public', name: 'report_public')]
    public function public(string $token, ScanRepository $scanRepository): Response
    {
        $scan = $scanRepository->findOneBy(['shareToken' => $token]);
        if (!$scan) throw $this->createNotFoundException();

        return $this->render('report/public.html.twig', ['scan' => $scan]);
    }

    #[Route('/report/{id}/share', name: 'report_share', methods: ['POST'])]
    public function generateShareLink(Scan $scan, EntityManagerInterface $em): JsonResponse
    {
        if ($scan->getProject()->getOwner() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        $scan->setShareToken(bin2hex(random_bytes(16)));
        $em->flush();

        return $this->json(['url' => $this->generateUrl('report_public', [
            'token' => $scan->getShareToken()
        ], UrlGeneratorInterface::ABSOLUTE_URL)]);
    }
}
