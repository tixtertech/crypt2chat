import os
import shutil

import yaml


def ensure_path_exists(file_path):
    directory = os.path.dirname(file_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as _:
            pass

class Conf:
    def __init__(self):
        config_path = './cache/server/config.yml'
        default_config_path = './server/default_conf.yml'
        if not os.path.exists(config_path):
            if not os.path.exists(default_config_path):
                raise FileNotFoundError(f"{default_config_path} unreachable.")
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            shutil.copy(default_config_path, config_path)
        with open(config_path, 'r', encoding='utf-8') as file:
            self.config = yaml.safe_load(file)

    def __call__(self, *args):
        output = self.config
        for arg in args:
            output = output[arg]
        return output

conf = Conf()