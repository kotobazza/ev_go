CREATE TABLE IF NOT EXISTS tempIDs (
    id SERIAL PRIMARY KEY,
    temp_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS votings (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    question TEXT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    audit_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS voting_options (
    id SERIAL PRIMARY KEY,
    voting_id INT NOT NULL,
    option_index INT NOT NULL,
    option_text TEXT NOT NULL
);