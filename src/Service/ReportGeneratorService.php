<?php


namespace App\Service;

use App\Entity\Scan;
use App\Entity\ScanReport;
use Doctrine\ORM\EntityManagerInterface;
use Dompdf\Dompdf;
use Dompdf\Options;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Twig\Environment;

class ReportGeneratorService
{
    public function __construct(
        private Environment $twig,
        private EntityManagerInterface $em,
        private ParameterBagInterface $params,
    ) {}

    public function generate(Scan $scan): string
    {
        $html = $this->twig->render('report/pdf.html.twig', [
            'scan' => $scan,
        ]);

        $options = new Options();
        $options->set('defaultFont', 'DejaVu Sans');
        $options->set('isHtml5ParserEnabled', true);

        $dompdf = new Dompdf($options);
        $dompdf->loadHtml($html);
        $dompdf->setPaper('A4', 'portrait');
        $dompdf->render();

        $pdfContent = $dompdf->output();

        // Sauvegarde sur disque
        $filename = sprintf('report_scan_%d_%s.pdf', $scan->getId(), date('Ymd_His'));
        $pdfDir   = $this->params->get('kernel.project_dir') . '/public/reports/';

        if (!is_dir($pdfDir)) {
            mkdir($pdfDir, 0755, true);
        }

        file_put_contents($pdfDir . $filename, $pdfContent);

        // Sauvegarde en BDD
        $report = $scan->getReport() ?? new ScanReport();
        $report->setScan($scan);
        $report->setPdfPath('/reports/' . $filename);
        $scan->setReport($report);
        $this->em->persist($report);
        $this->em->flush();

        return $pdfContent;
    }
}
