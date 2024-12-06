import logging
import logging.config
import os
import sqlite3
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta


class RequestsDB:
    def __init__(self, db_path):
       self.db_path = db_path
       self.conn = None
       self._init_db()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
            self.conn = None

    @property
    def conn_(self):
        """Get the current connection or create a new one if none exists."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
        return self.conn

    def _init_db(self):
       try:
           cursor = self.conn_.cursor()
           cursor.execute('''
               CREATE TABLE IF NOT EXISTS requests (
                   request DATETIME,
                   response DATETIME,
                   runtime FLOAT,
                   method TEXT,
                   url TEXT,
                   host TEXT,
                   port INTEGER,
                   response_code INTEGER
               )
           ''')
           self.conn_.commit()
       except sqlite3.Error as e:
           raise ValueError(f"Database initialization failed: {e}")

    def log_request(
            self,
            request: datetime,
            response: datetime,
            runtime: float,
            method: str,
            url: str,
            host: str,
            port: int,
            response_code: int
    ):
        try:
            cursor = self.conn_.cursor()
            cursor.execute('''
                        INSERT INTO requests (
                            request, response, runtime, 
                            method, url, host, port, response_code
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (request, response, runtime, method, url, host, port, response_code))
            self.conn_.commit()
        except sqlite3.Error as e:
            raise ValueError(f"Failed to log request: {e}")

    def get_per_ip(self):
        try:
            cursor = self.conn_.cursor()
            cursor.execute('''
                  SELECT host, method, COUNT(*), SUM(runtime)
                  FROM requests
                  GROUP BY host, method
              ''')
            results = cursor.fetchall()

            # Create a dictionary to hold the aggregated results
            aggregated_data = defaultdict(lambda: defaultdict(dict))

            # Process the results and store them in the dictionary
            for row in results:
                host, method, count, total_runtime = row
                aggregated_data[host][method] = {
                    "request_count": count,
                    "total_runtime": total_runtime
                }

            return dict(aggregated_data)

        except sqlite3.Error as e:
            raise ValueError(f"Failed to aggregate data per IP: {e}")



class Logging:
    def get_timestamp(self, line):
        try:
            return datetime.strptime(line.split(' - ')[0], "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def clear_logs(self):
        if os.path.exists(self.log_file):
            current_time = datetime.now(timezone.utc)
            delta = current_time - timedelta(days=1)

            with open(self.log_file, 'r') as f:
                lines = f.readlines()

            index = len(lines)
            for i, line in enumerate(lines):
                if line:
                    timestamp = self.get_timestamp(line)
                    if timestamp and timestamp >= delta:
                        index = min(index, i)
            with open(self.log_file, 'w') as f:
                f.writelines(lines[index:])

    def __init__(self, log_file):
        self.log_file = log_file
        self.clear_logs()

        logging.config.dictConfig({
            'version': 1,
            'disable_existing_loggers': True,
            'loggers': {
                'logger': {
                    'handlers': ['file'],
                    'level': 'DEBUG',
                    'propagate': False
                }
            },
            'handlers': {
                'file': {
                    'class': 'logging.FileHandler',
                    'filename': self.log_file,
                    'formatter': 'default'
                }
            },
            'formatters': {
                'default': {
                    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                }
            }
        })
        logging.Formatter.converter = time.gmtime

    def debug(self, *args, **kwargs):
        logging.getLogger('logger').debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        logging.getLogger('logger').info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        logging.getLogger('logger').warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        logging.getLogger('logger').error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        logging.getLogger('logger').debug(*args, **kwargs)


logging_ = Logging(os.getenv("SERVER_LOG_FILE"))
requests_ = RequestsDB(os.getenv("SERVER_REQUESTS_DB"))