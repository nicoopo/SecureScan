<?php

namespace App\Controller\Admin;

use App\Entity\Fix;

use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Config\Filters;

use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;

use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\CodeEditorField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IntegerField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextareaField;
use EasyCorp\Bundle\EasyAdminBundle\Filter\ChoiceFilter;

class FixCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return Fix::class;
    }

    public function configureCrud(Crud $crud): Crud
    {
        return $crud
            ->setEntityLabelInSingular('Correction')
            ->setEntityLabelInPlural('Corrections')

            ->setDefaultSort([
                'id' => 'DESC',
            ])

            ->setSearchFields([
                'type',
                'status',
                'filePath',
                'explanation',
            ]);
    }

    public function configureFilters(Filters $filters): Filters
    {
        return $filters

            ->add(
                ChoiceFilter::new('type')
                    ->setChoices([
                        'Template' => Fix::TYPE_TEMPLATE,
                        'IA'       => Fix::TYPE_AI,
                    ])
            )

            ->add(
                ChoiceFilter::new('status')
                    ->setChoices([
                        'Pending'  => Fix::STATUS_PENDING,
                        'Accepted' => Fix::STATUS_ACCEPTED,
                        'Rejected' => Fix::STATUS_REJECTED,
                    ])
            );
    }

    public function configureFields(string $pageName): iterable
    {
        return [

            IdField::new('id')
                ->hideOnForm(),

            AssociationField::new('finding')
                ->setLabel('Vulnérabilité'),

            ChoiceField::new('type')
                ->setLabel('Type')
                ->setChoices([
                    'Template' => Fix::TYPE_TEMPLATE,
                    'IA'       => Fix::TYPE_AI,
                ]),

            ChoiceField::new('status')
                ->setLabel('Statut')
                ->setChoices([
                    'Pending'  => Fix::STATUS_PENDING,
                    'Accepted' => Fix::STATUS_ACCEPTED,
                    'Rejected' => Fix::STATUS_REJECTED,
                ]),

            TextareaField::new('originalCode')
                ->setLabel('Code Original')
                ->hideOnIndex(),

            CodeEditorField::new('proposedCode')
                ->setLabel('Code Corrigé')
                ->setLanguage('php'),

            TextareaField::new('explanation')
                ->setLabel('Explication')
                ->hideOnIndex(),

            TextareaField::new('filePath')
                ->setLabel('Fichier')
                ->hideOnIndex(),

            IntegerField::new('lineStart')
                ->setLabel('Ligne Début')
                ->hideOnIndex(),

            IntegerField::new('lineEnd')
                ->setLabel('Ligne Fin')
                ->hideOnIndex(),

            DateTimeField::new('createdAt')
                ->setLabel('Créé le')
                ->hideOnForm(),

            DateTimeField::new('decidedAt')
                ->setLabel('Décidé le')
                ->hideOnForm(),
        ];
    }
}