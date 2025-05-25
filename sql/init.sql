-- Создание таблицы пользователей
CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    login VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL
);

-- Создание таблицы голосований
CREATE TABLE Votings (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    question TEXT NOT NULL
);

-- Создание таблицы вариантов ответов
CREATE TABLE VotingOptions (
    id SERIAL PRIMARY KEY,
    voting_id INTEGER NOT NULL,
    option_text TEXT NOT NULL,
    FOREIGN KEY (voting_id) REFERENCES Votings(id) ON DELETE CASCADE
);

-- Создание таблицы для хранения голосов пользователей
CREATE TABLE EncryptedVotes (
    id SERIAL PRIMARY KEY,
    voting_id INTEGER NOT NULL,
    vote_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    encrypted_data TEXT NOT NULL,
    FOREIGN KEY (voting_id) REFERENCES Votings(id)
);