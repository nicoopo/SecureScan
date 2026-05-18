<?php

namespace App\Controller\Admin;

use App\Entity\Scan;

use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;

use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;

use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IntegerField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;

class ScanCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return Scan::class;
    }

    public function configureActions(Actions $actions): Actions
    {
        return $actions
            ->add(Crud::PAGE_EDIT, Action::INDEX)
            ->add(Crud::PAGE_INDEX, Action::DETAIL)
            ->add(Crud::PAGE_EDIT, Action::DETAIL);
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
}