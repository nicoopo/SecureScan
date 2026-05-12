<?php

namespace App\Controller\Admin;

use App\Entity\Scan;
use App\Service\ScanService;

use Doctrine\ORM\EntityManagerInterface;

use Symfony\Component\HttpFoundation\RedirectResponse;

use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminRoute;

use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;

use EasyCorp\Bundle\EasyAdminBundle\Context\AdminContext;

use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;

use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IntegerField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextareaField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;

class ScanCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return Scan::class;
    }

    public function configureCrud(Crud $crud): Crud
    {
        return $crud
            ->setEntityLabelInSingular('Scan')
            ->setEntityLabelInPlural('Scans')

            ->setDefaultSort([
                'id' => 'DESC',
            ])

            ->setSearchFields([
                'status',
                'grade',
                'fixBranch',
                'project.name',
            ]);
    }

    public function configureActions(Actions $actions): Actions
    {
        $runScan = Action::new('runScan', 'Lancer Scan')
            ->linkToCrudAction('runScan');

        return $actions
            ->add(Crud::PAGE_INDEX, $runScan)
            ->add(Crud::PAGE_DETAIL, $runScan);
    }

    public function configureFields(string $pageName): iterable
    {
        return [

            IdField::new('id')
                ->hideOnForm(),

            AssociationField::new('project')
                ->setLabel('Projet'),

            ChoiceField::new('status')
                ->setLabel('Statut')
                ->setChoices([
                    'Pending' => Scan::STATUS_PENDING,
                    'Running' => Scan::STATUS_RUNNING,
                    'Done' => Scan::STATUS_DONE,
                    'Failed' => Scan::STATUS_FAILED,
                ]),

            IntegerField::new('score')
                ->setLabel('Score')
                ->hideOnForm(),

            ChoiceField::new('grade')
                ->setLabel('Grade')
                ->setChoices([
                    'A' => Scan::GRADE_A,
                    'B' => Scan::GRADE_B,
                    'C' => Scan::GRADE_C,
                    'D' => Scan::GRADE_D,
                    'F' => Scan::GRADE_F,
                ])
                ->hideOnForm(),

            DateTimeField::new('startedAt')
                ->setLabel('Début du scan')
                ->hideOnForm(),

            DateTimeField::new('finishedAt')
                ->setLabel('Fin du scan')
                ->hideOnForm(),

          
            TextField::new('fixBranch')
                ->setLabel('Branche Git')
                ->hideOnIndex(),

            AssociationField::new('findings')
                ->setLabel('Vulnérabilités')
                ->hideOnIndex(),

            AssociationField::new('report')
                ->setLabel('Rapport')
                ->hideOnIndex(),
        ];
    }

    #[AdminRoute(path: '/scan/{entityId}/run', name: 'admin_scan_run')]
    public function runScan(
        AdminContext $context,
        ScanService $scanService,
        EntityManagerInterface $em
    ): RedirectResponse {

        /** @var Scan $scan */
        $scan = $context->getEntity()->getInstance();

        $project = $scan->getProject();

        if (!$project || !$project->getLocalPath()) {

            $this->addFlash(
                'danger',
                'Le projet ne possède aucun chemin local.'
            );

            return $this->redirect(
                $this->generateUrl('admin')
            );
        }

        $scanService->runScan(
            $scan,
            $project->getLocalPath()
        );

        $this->addFlash(
            'success',
            'Le scan a été lancé avec succès.'
        );

        return $this->redirect(
            $this->generateUrl('admin')
        );
    }
}