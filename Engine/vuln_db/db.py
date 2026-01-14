import psycopg2
from dotenv import dotenv_values
import os

current_directory = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_directory, '.', ".env")
# Load the database credentials from the .env file
config = dotenv_values(env_path)

# Connect to the PostgreSQL database
def connect():
    try:
        conn = psycopg2.connect(
            host=config["DB_HOST"],
            port=config["DB_PORT"],
            database=config["DB_NAME"],
            user=config["DB_USER"],
            password=config["DB_PASSWORD"]
        )
        return conn
    except psycopg2.Error as e:
        print("Error connecting to the database:", e)

# Close the database connection
def close_connection(conn):
    try:
        conn.close()
    except psycopg2.Error as e:
        print("Error closing the database connection:", e)