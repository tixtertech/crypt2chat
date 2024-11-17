import logging
import logging.config
import os


class Logging:
    def __init__(self, log_file):
        self.log_file = log_file

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