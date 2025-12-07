import configparser
import os


class Config:
    def __init__(self, config_file):
        self.config_file = config_file


    def read_config(self):
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config

    def load_env(self):
        config = open(self.config_file, "r")
        #print(config.read())
        for line in config.readlines():
            line = line.strip()
            print(line)
            print(f"{line.split("=")[1].strip()}")
            os.environ[line.split("=")[0].strip()] = line.split("=")[1].strip()
