<?php

namespace App\Controller\Admin;

use App\Entity\Scan;
use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IntegerField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextareaField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;

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
            ->setSearchFields([
                'status',
                'grade',
                'fixBranch'
            ]);
    }

    public function configureFields(string $pageName): iterable
    {
        return [

            AssociationField::new('project'),

            ChoiceField::new('status')
                ->setChoices([
                    'Pending' => 'pending',
                    'Running' => 'running',
                    'Done' => 'done',
                    'Failed' => 'failed',
                ]),

            IntegerField::new('score'),

            ChoiceField::new('grade')
                ->setChoices([
                    'A' => 'A',
                    'B' => 'B',
                    'C' => 'C',
                    'D' => 'D',
                    'F' => 'F',
                ]),

            DateTimeField::new('startedAt')
                ->hideOnForm(),

            DateTimeField::new('finishedAt')
                ->hideOnForm(),

            TextareaField::new('errorMessage')
                ->hideOnIndex(),

            TextField::new('fixBranch')
                ->hideOnIndex(),

            AssociationField::new('findings')
                ->hideOnIndex(),

            AssociationField::new('report')
                ->hideOnIndex(),
        ];
    }
}