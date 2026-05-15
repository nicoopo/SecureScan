<?php

namespace App\Controller\Admin;

use App\Entity\ScanReport;
use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ArrayField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextareaField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;

class ScanReportCrudController extends AbstractCrudController
{

    public function configureActions(Actions $actions): Actions
    {
        return $actions
        ->add(Crud:: PAGE_EDIT, Action::INDEX)
        ->add(Crud:: PAGE_INDEX, Action::DETAIL)
        ->add(Crud:: PAGE_EDIT, Action::DETAIL);

    }
    public static function getEntityFqcn(): string
    {
        return ScanReport::class;
    }

    public function configureCrud(Crud $crud): Crud
    {
        return $crud
            ->setEntityLabelInSingular('Rapport')
            ->setEntityLabelInPlural('Rapports')
            ->setSearchFields([
                'pdfPath'
            ]);
    }

    public function configureFields(string $pageName): iterable
    {
        return [

            AssociationField::new('scan'),

            TextareaField::new('htmlContent')
                ->hideOnIndex(),

            TextField::new('pdfPath')
                ->hideOnIndex(),

            ArrayField::new('summary')
                ->hideOnIndex(),

            DateTimeField::new('generatedAt')
                ->hideOnForm(),
        ];
    }
}