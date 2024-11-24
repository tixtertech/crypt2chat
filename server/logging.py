import logging
import logging.config
import os
import time
from datetime import datetime, timezone, timedelta


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
                'middleware_logger': {
                    'handlers': ['file'],
                    'level': 'DEBUG',
                    'propagate': False
                },
                'app_logger': {
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

    def app_debug(self, *args, **kwargs):
        logging.getLogger('app_logger').debug(*args, **kwargs)

    def app_info(self, *args, **kwargs):
        logging.getLogger('app_logger').info(*args, **kwargs)

    def app_warning(self, *args, **kwargs):
        logging.getLogger('app_logger').warning(*args, **kwargs)

    def app_error(self, *args, **kwargs):
        logging.getLogger('app_logger').error(*args, **kwargs)

    def app_critical(self, *args, **kwargs):
        logging.getLogger('app_logger').debug(*args, **kwargs)

    def middleware_debug(self, *args, **kwargs):
        logging.getLogger('middleware_logger').debug(*args, **kwargs)

    def middleware_info(self, *args, **kwargs):
        logging.getLogger('middleware_logger').info(*args, **kwargs)

    def middleware_warning(self, *args, **kwargs):
        logging.getLogger('middleware_logger').warning(*args, **kwargs)

    def middleware_error(self, *args, **kwargs):
        logging.getLogger('middleware_logger').error(*args, **kwargs)

    def middleware_critical(self, *args, **kwargs):
        logging.getLogger('middleware_logger').debug(*args, **kwargs)


logging_ = Logging(os.getenv("SERVER_LOG_FILE"))