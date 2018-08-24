# coding = utf-8

from app import Client
import requirements

if __name__ == '__main__':
    project = requirements.project
    token = requirements.token
    key = requirements.key
    Client(project, token, key)
