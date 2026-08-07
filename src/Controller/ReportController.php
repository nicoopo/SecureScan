<?php

namespace App\Controller;

use App\Entity\Fix;
use App\Entity\Scan;
use App\Repository\ScanRepository;
use App\Service\ChartService;
use App\Service\FixApplierService;
use App\Service\GitFixWorkflowService;
use App\Service\GitHubPushService;
use App\Service\ReportGeneratorService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

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

    #[Route('/report/fix/{id}/accept', name: 'fix_accept', methods: ['POST'])]
    public function acceptFix(Fix $fix, Request $request, CsrfTokenManagerInterface $csrfTokenManager, FixApplierService $fixApplier, GitFixWorkflowService $gitWorkflow, EntityManagerInterface $em): JsonResponse
    {
        $this->assertFixOwner($fix);
        $this->assertValidCsrf($request, $csrfTokenManager);

        $fix->accept();
        $em->flush();

        $result = $fixApplier->apply($fix);
        $scan   = $fix->getFinding()?->getScan();
        $fixBranch = null;

        if ($result['applied'] && $scan) {
            $fixBranch = $gitWorkflow->ensureFixBranch($scan);
            $gitWorkflow->commitFix(
                $scan,
                $fix->getFilePath(),
                sprintf('[SecureScan] %s : %s', $fix->getFinding()->getOwaspCategory(), $fix->getFinding()->getTitle())
            );
            $em->flush();
        }

        return $this->json([
            'status'    => $fix->getStatus(),
            'applied'   => $result['applied'],
            'message'   => $result['message'],
            'fixBranch' => $fixBranch,
        ]);
    }

    #[Route('/report/{id}/push-fixes', name: 'report_push_fixes', methods: ['POST'])]
    public function pushFixes(Scan $scan, Request $request, CsrfTokenManagerInterface $csrfTokenManager, GitHubPushService $gitHubPush): JsonResponse
    {
        if ($scan->getProject()->getOwner() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }
        $this->assertValidCsrf($request, $csrfTokenManager, 'push_fixes');

        return $this->json($gitHubPush->push($scan));
    }

    #[Route('/report/fix/{id}/reject', name: 'fix_reject', methods: ['POST'])]
    public function rejectFix(Fix $fix, Request $request, CsrfTokenManagerInterface $csrfTokenManager, EntityManagerInterface $em): JsonResponse
    {
        $this->assertFixOwner($fix);
        $this->assertValidCsrf($request, $csrfTokenManager);

        $fix->reject();
        $em->flush();

        return $this->json(['status' => $fix->getStatus()]);
    }

    private function assertFixOwner(Fix $fix): void
    {
        $owner = $fix->getFinding()?->getScan()?->getProject()?->getOwner();
        if ($owner !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }
    }

    private function assertValidCsrf(Request $request, CsrfTokenManagerInterface $csrfTokenManager, string $tokenId = 'fix_action'): void
    {
        $token = $request->headers->get('X-CSRF-Token', '');
        if (!$csrfTokenManager->isTokenValid(new CsrfToken($tokenId, $token))) {
            throw $this->createAccessDeniedException('Jeton CSRF invalide.');
        }
    }
}
