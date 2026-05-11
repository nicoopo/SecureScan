<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20260511082943 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('CREATE TABLE finding (id INT AUTO_INCREMENT NOT NULL, tool VARCHAR(50) NOT NULL, severity VARCHAR(20) NOT NULL, owasp_category VARCHAR(3) NOT NULL, file_path VARCHAR(512) DEFAULT NULL, line INT DEFAULT NULL, rule_id VARCHAR(255) DEFAULT NULL, title VARCHAR(255) NOT NULL, description LONGTEXT DEFAULT NULL, code_snippet LONGTEXT DEFAULT NULL, raw_data JSON DEFAULT NULL, scan_id INT NOT NULL, INDEX IDX_A71913362827AAD3 (scan_id), INDEX idx_finding_severity (severity), INDEX idx_finding_owasp (owasp_category), INDEX idx_finding_tool (tool), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE fix (id INT AUTO_INCREMENT NOT NULL, type VARCHAR(20) NOT NULL, status VARCHAR(20) NOT NULL, original_code LONGTEXT DEFAULT NULL, proposed_code LONGTEXT NOT NULL, explanation LONGTEXT DEFAULT NULL, file_path VARCHAR(512) DEFAULT NULL, line_start INT DEFAULT NULL, line_end INT DEFAULT NULL, created_at DATETIME NOT NULL, decided_at DATETIME DEFAULT NULL, finding_id INT NOT NULL, INDEX IDX_59FA47604323B5E7 (finding_id), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE project (id INT AUTO_INCREMENT NOT NULL, name VARCHAR(255) NOT NULL, repository_url VARCHAR(512) DEFAULT NULL, zip_path VARCHAR(512) DEFAULT NULL, local_path VARCHAR(512) DEFAULT NULL, source VARCHAR(20) NOT NULL, language VARCHAR(30) NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME DEFAULT NULL, owner_id INT NOT NULL, INDEX IDX_2FB3D0EE7E3C61F9 (owner_id), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE scan (id INT AUTO_INCREMENT NOT NULL, status VARCHAR(20) NOT NULL, score INT DEFAULT NULL, grade VARCHAR(1) DEFAULT NULL, started_at DATETIME NOT NULL, finished_at DATETIME DEFAULT NULL, error_message LONGTEXT DEFAULT NULL, fix_branch VARCHAR(255) DEFAULT NULL, project_id INT NOT NULL, INDEX IDX_C4B3B3AE166D1F9C (project_id), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE scan_report (id INT AUTO_INCREMENT NOT NULL, html_content LONGTEXT DEFAULT NULL, pdf_path VARCHAR(512) DEFAULT NULL, summary JSON DEFAULT NULL, generated_at DATETIME NOT NULL, scan_id INT NOT NULL, UNIQUE INDEX UNIQ_189E527A2827AAD3 (scan_id), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE `user` (id INT AUTO_INCREMENT NOT NULL, email VARCHAR(180) NOT NULL, full_name VARCHAR(100) NOT NULL, roles JSON NOT NULL, password VARCHAR(255) NOT NULL, git_token VARCHAR(512) DEFAULT NULL, git_username VARCHAR(100) DEFAULT NULL, created_at DATETIME NOT NULL, updated_at DATETIME DEFAULT NULL, UNIQUE INDEX UNIQ_8D93D649E7927C74 (email), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('CREATE TABLE messenger_messages (id BIGINT AUTO_INCREMENT NOT NULL, body LONGTEXT NOT NULL, headers LONGTEXT NOT NULL, queue_name VARCHAR(190) NOT NULL, created_at DATETIME NOT NULL, available_at DATETIME NOT NULL, delivered_at DATETIME DEFAULT NULL, INDEX IDX_75EA56E0FB7336F0E3BD61CE16BA31DBBF396750 (queue_name, available_at, delivered_at, id), PRIMARY KEY (id)) DEFAULT CHARACTER SET utf8mb4');
        $this->addSql('ALTER TABLE finding ADD CONSTRAINT FK_A71913362827AAD3 FOREIGN KEY (scan_id) REFERENCES scan (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE fix ADD CONSTRAINT FK_59FA47604323B5E7 FOREIGN KEY (finding_id) REFERENCES finding (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE project ADD CONSTRAINT FK_2FB3D0EE7E3C61F9 FOREIGN KEY (owner_id) REFERENCES `user` (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE scan ADD CONSTRAINT FK_C4B3B3AE166D1F9C FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE');
        $this->addSql('ALTER TABLE scan_report ADD CONSTRAINT FK_189E527A2827AAD3 FOREIGN KEY (scan_id) REFERENCES scan (id) ON DELETE CASCADE');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('ALTER TABLE finding DROP FOREIGN KEY FK_A71913362827AAD3');
        $this->addSql('ALTER TABLE fix DROP FOREIGN KEY FK_59FA47604323B5E7');
        $this->addSql('ALTER TABLE project DROP FOREIGN KEY FK_2FB3D0EE7E3C61F9');
        $this->addSql('ALTER TABLE scan DROP FOREIGN KEY FK_C4B3B3AE166D1F9C');
        $this->addSql('ALTER TABLE scan_report DROP FOREIGN KEY FK_189E527A2827AAD3');
        $this->addSql('DROP TABLE finding');
        $this->addSql('DROP TABLE fix');
        $this->addSql('DROP TABLE project');
        $this->addSql('DROP TABLE scan');
        $this->addSql('DROP TABLE scan_report');
        $this->addSql('DROP TABLE `user`');
        $this->addSql('DROP TABLE messenger_messages');
    }
}
