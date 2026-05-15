<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260513080239 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE scan DROP FOREIGN KEY `FK_C4B3B3AEA76ED395`');
        $this->addSql('DROP INDEX IDX_C4B3B3AEA76ED395 ON scan');
        $this->addSql('ALTER TABLE scan DROP user_id');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE scan ADD user_id INT DEFAULT NULL');
        $this->addSql('ALTER TABLE scan ADD CONSTRAINT `FK_C4B3B3AEA76ED395` FOREIGN KEY (user_id) REFERENCES user (id) ON UPDATE NO ACTION ON DELETE NO ACTION');
        $this->addSql('CREATE INDEX IDX_C4B3B3AEA76ED395 ON scan (user_id)');
    }
}
