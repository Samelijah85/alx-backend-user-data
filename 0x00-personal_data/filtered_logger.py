#!/usr/bin/env python3
"""
Module filtered_logger

Personal data
"""
import logging
import os
import re
from typing import List
from mysql.connector import connection, Error as MySQLConnectionError

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    A function that redacts sensitive information from a message based on
    specified fields.

    Parameters:
        - fields: a list of strings representing the fields to redact.
        - redaction: a string representing the redacted value.
        - message: a string representing the message containing the sensitive
        data.
        - separator: a string representing the separator between key-value
        pairs in the message.

    Returns:
        The message with sensitive information redacted.
    """
    for field in fields:
        message = re.sub(rf"{field}=(.*?)\{separator}",
                         f'{field}={redaction}{separator}', message)
    return message


class RedactingFormatter(logging.Formatter):
    """ RedactingFormatter class. """
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes the RedactingFormatter object.

        Parameters:
            - fields: a list of strings representing the fields to redact.

        Returns:
            None
        """
        self.fields = fields
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the input record by redacting sensitive information based on
        specified fields.

        Parameters:
            - record: a logging LogRecord object containing the log record to
            format.

        Returns:
            The formatted log record as a string.
        """

        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def get_logger() -> logging.Logger:
    """
    Returns a logger that logs sensitive information redacted
    """
    user_data_logger = logging.getLogger("user_data")
    user_data_logger.setLevel(logging.INFO)
    user_data_logger.propagate = False
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    user_data_logger.addHandler(stream_handler)
    return user_data_logger


def get_db() -> connection.MySQLConnection:
    """
    Returns a connection to the personal data database.
    """
    db_password = os.environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    db_username = os.environ.get('PERSONAL_DATA_DB_USERNAME', "root")
    db_host = os.environ.get('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.environ.get('PERSONAL_DATA_DB_NAME')
    try:
        conn = connection.MySQLConnection(
            host=db_host,
            database=db_name,
            user=db_username,
            password=db_password)
        return conn
    except MySQLConnectionError as err:
        print(f"Error: {err}.")
        return None


def main() -> None:
    """
    Implement a main function
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    for row in cursor:
        message = f"name={row[0]}; email={row[1]}; phone={row[2]}; " +\
            f"ssn={row[3]}; password={row[4]};ip={row[5]}; " +\
            f"last_login={row[6]}; user_agent={row[7]};"
        print(message)
    cursor.close()
    db.close()


if __name__ == '__main__':
    main()
