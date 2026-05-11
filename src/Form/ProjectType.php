<?php
namespace App\Form;

use App\Entity\Project;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\Extension\Core\Type\FileType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\File;

class ProjectType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('name', TextType::class, [
                'label' => 'Nom du projet',
            ])
            ->add('source', ChoiceType::class, [
                'label' => 'Source',
                'choices' => [
                    'URL Git' => Project::SOURCE_GIT,
                    'Archive ZIP' => Project::SOURCE_ZIP,
                ],
            ])
            ->add('repositoryUrl', TextType::class, [
                'label' => 'URL du repository Git',
                'required' => false,
            ])
            ->add('zipFile', FileType::class, [
                'label' => 'Archive ZIP',
                'mapped' => false,
                'required' => false,
            ])
        ;
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Project::class,
        ]);
    }
}
