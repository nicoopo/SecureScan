<?php

namespace App\Controller\Admin;

use App\Entity\Finding;
use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;

use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\CodeEditorField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IntegerField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextareaField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;

class FindingCrudController extends AbstractCrudController
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
        return Finding::class;
    }

    public function configureCrud(Crud $crud): Crud
    {
        return $crud
            ->setEntityLabelInSingular('Finding')
            ->setEntityLabelInPlural('Findings')
            ->setSearchFields([
                'title',
                'tool',
                'severity',
                'owaspCategory',
                'filePath',
            ]);
    }

    public function configureFields(string $pageName): iterable
    {
        return [

            AssociationField::new('scan'),

            TextField::new('tool'),

            ChoiceField::new('severity')
                ->setChoices([
                    'Critical' => 'critical',
                    'High' => 'high',
                    'Medium' => 'medium',
                    'Low' => 'low',
                ]),

            ChoiceField::new('owaspCategory')
                ->setChoices([
                    'A01' => 'A01',
                    'A02' => 'A02',
                    'A03' => 'A03',
                    'A04' => 'A04',
                    'A05' => 'A05',
                    'A06' => 'A06',
                    'A07' => 'A07',
                    'A08' => 'A08',
                    'A09' => 'A09',
                    'A10' => 'A10',
                ]),

            TextField::new('title'),

            TextField::new('filePath')
                ->hideOnIndex(),

            IntegerField::new('line')
                ->hideOnIndex(),

            TextField::new('ruleId')
                ->hideOnIndex(),

            TextareaField::new('description')
                ->hideOnIndex(),

            CodeEditorField::new('codeSnippet')
                ->hideOnIndex(),

            AssociationField::new('fixes')
                ->hideOnIndex(),
        ];
    }
}