DO
$$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'forensic_db') THEN
      CREATE DATABASE forensic_db;
   END IF;
END
$$;

DO
$$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'forensic_admin') THEN
      CREATE USER forensic_admin WITH ENCRYPTED PASSWORD 'SuperSecure123';
      GRANT ALL PRIVILEGES ON DATABASE forensic_db TO forensic_admin;
   END IF;
END
$$;