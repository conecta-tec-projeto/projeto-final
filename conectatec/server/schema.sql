CREATE DATABASE IF NOT EXISTS conectatec CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE conectatec;
CREATE TABLE IF NOT EXISTS users (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 name VARCHAR(140) NOT NULL,
 email VARCHAR(190) NOT NULL UNIQUE,
 password_hash VARCHAR(255) NOT NULL,
 role ENUM('cliente','tecnico') NOT NULL,
 phone VARCHAR(30), address VARCHAR(255), bio TEXT,
 specialties JSON, available_days JSON, portfolio JSON,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requests (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 client_id BIGINT UNSIGNED NOT NULL,
 technician_id BIGINT UNSIGNED NULL,
 directed_to BIGINT UNSIGNED NULL,
 device VARCHAR(180) NOT NULL, description TEXT NOT NULL,
 category VARCHAR(100), service_type ENUM('Presencial','Remoto') NOT NULL,
 priority ENUM('Baixa','Média','Crítica') NOT NULL DEFAULT 'Média', desired_deadline VARCHAR(120),
 status ENUM('enviada','aceita','diagnostico','orcamento','aguardando_aprovacao','manutencao','concluido','cancelado') NOT NULL DEFAULT 'enviada',
 diagnosis TEXT,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 FOREIGN KEY (client_id) REFERENCES users(id),
 FOREIGN KEY (technician_id) REFERENCES users(id),
 FOREIGN KEY (directed_to) REFERENCES users(id),
 INDEX idx_status (status), INDEX idx_client (client_id), INDEX idx_technician (technician_id)
);
CREATE TABLE IF NOT EXISTS quotes (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 request_id BIGINT UNSIGNED NOT NULL,
 technician_id BIGINT UNSIGNED NOT NULL,
 parts DECIMAL(12,2) NOT NULL DEFAULT 0,
 labor DECIMAL(12,2) NOT NULL DEFAULT 0,
 estimated_days INT NOT NULL,
 diagnosis TEXT NOT NULL,
 status ENUM('pendente','aprovado','recusado') NOT NULL DEFAULT 'pendente',
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY (request_id) REFERENCES requests(id),
 FOREIGN KEY (technician_id) REFERENCES users(id), INDEX idx_request (request_id)
);
CREATE TABLE IF NOT EXISTS messages (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 request_id BIGINT UNSIGNED NOT NULL,
 sender_id BIGINT UNSIGNED NOT NULL,
 body TEXT NOT NULL,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY (request_id) REFERENCES requests(id),
 FOREIGN KEY (sender_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS payments (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 request_id BIGINT UNSIGNED NOT NULL UNIQUE,
 method ENUM('Pix','Dinheiro','Transferência','Cartão','Outro') NOT NULL,
 installments TINYINT UNSIGNED NOT NULL DEFAULT 1,
 amount DECIMAL(12,2) NOT NULL,
 status ENUM('pendente','informado','confirmado') NOT NULL DEFAULT 'informado',
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY (request_id) REFERENCES requests(id)
);
CREATE TABLE IF NOT EXISTS password_resets (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 user_id BIGINT UNSIGNED NOT NULL,
 token_hash CHAR(64) NOT NULL UNIQUE,
 expires_at DATETIME NOT NULL,
 used_at DATETIME NULL,
 FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS request_photos (
 id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 request_id BIGINT UNSIGNED NOT NULL,
 mime VARCHAR(40) NOT NULL DEFAULT 'image/jpeg',
 data MEDIUMBLOB NOT NULL,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE,
 INDEX idx_photo_request (request_id)
);
CREATE TABLE IF NOT EXISTS request_hidden (
 request_id BIGINT UNSIGNED NOT NULL,
 user_id BIGINT UNSIGNED NOT NULL,
 PRIMARY KEY (request_id, user_id),
 FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE,
 FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
