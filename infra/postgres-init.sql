\getenv app_password SENTINELFLOW_DB_PASSWORD
CREATE ROLE sentinelflow_app LOGIN PASSWORD :'app_password';
ALTER DATABASE sentinelflow OWNER TO sentinelflow_app;