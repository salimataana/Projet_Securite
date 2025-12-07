# -*- coding: utf-8 -*-

from config import Config
from controller import blueprints

config = Config(".env")
config.load_env()

print("hello")


from flask import Flask

def create_app():
    application = Flask(__name__)
    for blueprint in blueprints:
        application.register_blueprint(blueprint)
    return application

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)