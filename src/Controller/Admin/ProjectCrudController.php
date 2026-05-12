<?php

namespace App\Controller\Admin;

use App\Entity\Project;
use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;

class ProjectCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return Project::class;
    }

    public function configureCrud(Crud $crud): Crud
    {
        return $crud
            ->setEntityLabelInSingular('Projet')
            ->setEntityLabelInPlural('Projets')
            ->setSearchFields([
                'name',
                'repositoryUrl',
                'language'
            ]);
    }

    public function configureFields(string $pageName): iterable
    {
        return [

            AssociationField::new('owner'),

            TextField::new('name'),

            TextField::new('repositoryUrl')
                ->hideOnIndex(),

            TextField::new('zipPath')
                ->hideOnIndex()
                ->hideOnForm(),

            TextField::new('localPath')
                ->hideOnIndex()
                ->hideOnForm(),

            ChoiceField::new('source')
                ->setChoices([
                    'Git Repository' => 'git',
                    'ZIP Upload' => 'zip',
                ]),

            ChoiceField::new('language')
                ->setChoices([
                    'PHP' => 'php',
                    'JavaScript' => 'javascript',
                    'Python' => 'python',
                    'NodeJS' => 'nodejs',
                    'Unknown' => 'unknown',
                ]),

            DateTimeField::new('createdAt')
                ->hideOnForm(),

            DateTimeField::new('updatedAt')
                ->hideOnForm(),
        ];
    }
}