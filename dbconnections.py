from pymongo import MongoClient


class MetaSingleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(MetaSingleton,cls).__call__(*args,**kwargs)
        return cls._instances[cls]


class MongoConnection(metaclass=MetaSingleton):

    def __init__(self, port=27017):
        self._connection = None
        self._db = None
        self.port = port
        """
        if not MongoConnection._instance:
            self.client = MongoClient(port=port)
            self.db = self.client.maldb
        else:
            pass
        """

    def connect(self):
        if self._connection is None:
            self._connection = MongoClient(port=self.port)
            self._db = self._connection.maldb

    def put_data(self, data):
        if self._connection is None:
            raise Exception("Please first connect to the server first")
        self._db.analysed_malware.insert_one(data)

    def get_data(self, id):
        if self._connection is None:
            raise Exception("Please first connect to the server first")
        return self._db.analysed_malware.find_one({'hash': id})


