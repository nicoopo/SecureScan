<?php

namespace App\Controller\Admin;

use App\Entity\User;

use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;

use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;

use EasyCorp\Bundle\EasyAdminBundle\Context\AdminContext;

use EasyCorp\Bundle\EasyAdminBundle\Dto\EntityDto;

use EasyCorp\Bundle\EasyAdminBundle\Config\KeyValueStore;

use EasyCorp\Bundle\EasyAdminBundle\Field\BooleanField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\EmailField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;

use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;

use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormEvents;

use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserCrudController extends AbstractCrudController
{
    public function __construct(
        private UserPasswordHasherInterface $userPasswordHasher
    ) {
    }

    public static function getEntityFqcn(): string
    {
        return User::class;
    }

    public function configureCrud(Crud $crud): Crud
    {
        return $crud
            ->setEntityLabelInSingular('Utilisateur')
            ->setEntityLabelInPlural('Utilisateurs')

            ->setDefaultSort([
                'id' => 'DESC',
            ])

            ->setSearchFields([
                'email',
                'fullName',
                'gitUsername',
            ]);
    }

    public function configureFields(string $pageName): iterable
    {
        return [

            IdField::new('id')
                ->hideOnForm(),

            EmailField::new('email')
                ->setLabel('Email'),

            TextField::new('fullName')
                ->setLabel('Nom complet'),

            ChoiceField::new('roles')
                ->setLabel('Rôles')
                ->setChoices([
                    'Admin' => 'ROLE_ADMIN',
                    'User'  => 'ROLE_USER',
                ])
                ->allowMultipleChoices()
                ->renderExpanded(),

            TextField::new('gitUsername')
                ->setLabel('Git Username'),

            BooleanField::new('isVerified')
                ->setLabel('Compte vérifié'),

            DateTimeField::new('createdAt')
                ->setLabel('Créé le')
                ->hideOnForm(),

            DateTimeField::new('updatedAt')
                ->setLabel('Mis à jour le')
                ->hideOnForm(),

            TextField::new('plainPassword')
                ->setLabel('Mot de passe')
                ->setFormType(RepeatedType::class)
                ->setFormTypeOptions([

                    'type' => PasswordType::class,

                    'first_options' => [
                        'label' => 'Mot de passe',
                    ],

                    'second_options' => [
                        'label' => 'Confirmation du mot de passe',
                    ],

                    'mapped' => false,
                ])
                ->setRequired($pageName === Crud::PAGE_NEW)
                ->onlyOnForms(),
        ];
    }

    public function createNewFormBuilder(
        EntityDto $entityDto,
        KeyValueStore $formOptions,
        AdminContext $context
    ): FormBuilderInterface {

        $formBuilder = parent::createNewFormBuilder(
            $entityDto,
            $formOptions,
            $context
        );

        return $this->addPasswordEventListener($formBuilder);
    }

    public function createEditFormBuilder(
        EntityDto $entityDto,
        KeyValueStore $formOptions,
        AdminContext $context
    ): FormBuilderInterface {

        $formBuilder = parent::createEditFormBuilder(
            $entityDto,
            $formOptions,
            $context
        );

        return $this->addPasswordEventListener($formBuilder);
    }

    private function addPasswordEventListener(
        FormBuilderInterface $formBuilder
    ): FormBuilderInterface {

        return $formBuilder->addEventListener(
            FormEvents::POST_SUBMIT,
            function ($event) {

                $form = $event->getForm();

                if (!$form->isValid()) {
                    return;
                }

                /** @var User $user */
                $user = $form->getData();

                $password = $form->get('plainPassword')->getData();

                if (!$password) {
                    return;
                }

                $hashedPassword = $this->userPasswordHasher
                    ->hashPassword($user, $password);

                $user->setPassword($hashedPassword);
            }
        );
    }
}