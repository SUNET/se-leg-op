from pyop.storage import MongoWrapper


class OpStorageWrapper(MongoWrapper):
    def __init__(self, db_uri, collection):
        super().__init__(db_uri, 'seleg_op', collection)
