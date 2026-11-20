-- PostgreSQL database dump
CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(50), password_hash VARCHAR(128));
INSERT INTO users VALUES (1, 'admin', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW');
