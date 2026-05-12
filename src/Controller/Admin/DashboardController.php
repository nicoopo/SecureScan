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
use EasyCorp\Bundle\EasyAdminBundle\Router\AdminUrlGenerator;

use Symfony\Component\HttpFoundation\Response;

#[AdminDashboard(routePath: '/admin', routeName: 'admin')]
class DashboardController extends AbstractDashboardController
{
    public function index(): Response
    {
        return $this->redirectToRoute('admin_user_index');
    }

    public function configureDashboard(): Dashboard
    {
        return Dashboard::new()
            ->setTitle('SecureScan');
    }

  public function configureMenuItems(): iterable
{
    yield MenuItem::linkToDashboard('Dashboard', 'fa fa-home');

    yield MenuItem::linkToRoute('Users', 'fas fa-users', 'admin_user_index');

    yield MenuItem::linkToRoute('Projects', 'fas fa-folder', 'admin_project_index');

    yield MenuItem::linkToRoute('Scans', 'fas fa-shield-alt', 'admin_scan_index');

    yield MenuItem::linkToRoute('Reports', 'fas fa-file-alt', 'admin_scan_report_index');

    yield MenuItem::linkToRoute('Findings', 'fas fa-bug', 'admin_finding_index');

    yield MenuItem::linkToRoute('Fixes', 'fas fa-tools', 'admin_fix_index');
}
}