<?php
namespace App\Controller\Admin;
use App\Entity\Finding;
use App\Entity\Fix;
use App\Entity\Project;
use App\Entity\Scan;
use App\Entity\ScanReport;
use App\Entity\User;
use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminDashboard;
use EasyCorp\Bundle\EasyAdminBundle\Config\Dashboard;
use EasyCorp\Bundle\EasyAdminBundle\Config\MenuItem;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractDashboardController;
use Symfony\Component\
HttpFoundation\Response;
#[AdminDashboard(routePath: '/admin', routeName: 'admin')]class DashboardController extends AbstractDashboardController{
    public function configureDashboard(): Dashboard{
        return Dashboard::new()
            ->setTitle('SecureScan — Admin');
    }

    public function configureMenuItems(): iterable{
        yield MenuItem::linkToDashboard('Dashboard', 'fa fa-home');
        yield MenuItem::section('Contenu');
        yield MenuItem::linkToCrud('Projets', 'fa fa-folder', Project::class);
        yield MenuItem::linkToCrud('Scans', 'fa fa-shield-alt', Scan::class);
        yield MenuItem::linkToCrud('Findings', 'fa fa-bug', Finding::class);
        yield MenuItem::linkToCrud('Fixes', 'fa fa-tools', Fix::class);
        yield MenuItem::linkToCrud('Rapports', 'fa fa-file-alt', ScanReport::class);
        yield MenuItem::section('Utilisateurs');
        yield MenuItem::linkToCrud('Utilisateurs', 'fa fa-users', User::class);
        yield MenuItem::section('');
        yield MenuItem::linkToUrl('← Retour au site', 'fa fa-arrow-left', '/');
    }
}
 