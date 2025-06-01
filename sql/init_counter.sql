CREATE TABLE IF NOT EXISTS votings (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    question TEXT NOT NULL,
    state INT NOT NULL,
    start_time TIMESTAMP NOT NULL,
    audit_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_votes (
    voting_id INT NOT NULL,
    label TEXT NOT NULL,
    encrypted_vote TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (voting_id) REFERENCES votings(id)
);


CREATE TABLE IF NOT EXISTS merklie_roots(
    id SERIAL PRIMARY KEY,
    voting_id INT NOT NULL,
    root_value TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (voting_id) REFERENCES votings(id)
);


CREATE TABLE IF NOT EXISTS public_encrypted_votes(
    voting_id INT NOT NULL,
    label TEXT NOT NULL,
    corresponds_to_merklie_root INT NOT NULL,
    encrypted_vote TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    moved_into_at TIMESTAMP NOT NULL,
    FOREIGN KEY (voting_id) REFERENCES votings(id),
    FOREIGN KEY (corresponds_to_merklie_root) REFERENCES merklie_roots(id)
);


CREATE TABLE IF NOT EXISTS results(
    id SERIAL PRIMARY KEY,
    voting_id INT NOT NULL,
    corresponds_to_merklie_root INT NOT NULL,
    resulted_count TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (voting_id) REFERENCES votings(id),
    FOREIGN KEY (corresponds_to_merklie_root) REFERENCES merklie_roots(id)
);


CREATE TABLE IF NOT EXISTS voting_options (
    id SERIAL PRIMARY KEY,
    voting_id INT NOT NULL,
    option_index INT NOT NULL,
    option_text TEXT NOT NULL,
    FOREIGN KEY (voting_id) REFERENCES votings(id)
);