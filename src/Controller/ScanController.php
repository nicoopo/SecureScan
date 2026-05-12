<?php
namespace App\Controller;

use App\Entity\Project;
use App\Entity\Scan;
use App\Form\ProjectType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Service\ScanOrchestrator;
use Symfony\Component\Routing\Attribute\Route;

final class ScanController extends AbstractController
{
    #[Route('/scan/new', name: 'app_scan_new')]
    public function new(Request $request, EntityManagerInterface $em, ScanOrchestrator $scanOrchestrator): Response
    {
        $project = new Project();
        $form = $this->createForm(ProjectType::class, $project);
        $form->handleRequest($request);
        if ($form->isSubmitted() && $form->isValid()) {
            $project->setOwner($this->getUser());
            $zipFile = $form->get('zipFile')->getData();
            if ($zipFile) {
                $project->setSource(Project::SOURCE_ZIP);
                $zipPath = '/var/www/html/var/uploads/' . uniqid() . '.zip';
                $zipFile->move('/var/www/html/var/uploads/', basename($zipPath));
                $project->setZipPath($zipPath);
            }
            $scan = new Scan();
            $project->addScan($scan);
            $em->persist($project);
            $em->persist($scan);
            $em->flush();
            $scanOrchestrator->run($scan);
            return $this->redirectToRoute('app_scan_detail', ['id' => $scan->getId()]);
        }
        return $this->render('scan/new.html.twig', [
            'form' => $form,
        ]);
    }

    #[Route('/scan', name: 'app_scan_list')]
    public function list(EntityManagerInterface $em): Response
    {
        $scans = $em->getRepository(Scan::class)->findBy(
            ['project' => array_map(fn($p) => $p->getId(), $this->getUser()->getProjects()->toArray())],
            ['id' => 'DESC']
        );

        return $this->render('scan/list.html.twig', [
            'scans' => $scans,
        ]);
    }

    #[Route('/scan/{id}', name: 'app_scan_detail')]
    public function detail(int $id, EntityManagerInterface $em): Response
    {
        $scan = $em->getRepository(Scan::class)->find($id);

        if (!$scan) {
            throw $this->createNotFoundException('Scan introuvable');
        }

        return $this->render('scan/detail.html.twig', [
            'scan' => $scan,
        ]);
    }
}
