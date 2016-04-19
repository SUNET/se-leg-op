# -*- coding: utf-8 -*-

import pytest
from se_leg_op.storage import MongoWrapper
from se_leg_op.storage import MongoTemporaryInstance

__author__ = 'lundberg'


@pytest.fixture()
def init_mongodb(request):
    request.instance.mongo_db = MongoTemporaryInstance()

    def shutdown_mongodb():
        request.instance.mongo_db.shutdown()

    request.addfinalizer(shutdown_mongodb)


@pytest.mark.usefixtures('init_mongodb')
class TestMongoStorage(object):

    @pytest.fixture()
    def db(self, request):
        return MongoWrapper(request.instance.mongo_db.get_uri(), 'se_leg_op', 'test')

    def test_write(self, db):
        db['foo'] = 'bar'
        assert db['foo'] == 'bar'

    def test_multilevel_dict(self, db):
        db['foo'] = {}
        assert db['foo'] == {}
        db['foo'] = {'bar': 'baz'}
        assert db['foo']['bar'] == 'baz'

    def test_contains(self, db):
        db['foo'] = 'bar'
        assert 'foo' in db

    def test_pop(self, db):
        db['foo'] = 'bar'
        assert db.pop('foo') == 'bar'
        try:
            db['foo']
        except Exception as e:
            assert isinstance(e, KeyError)

    def test_items(self, db):
        db['foo'] = 'foorbar'
        db['bar'] = True
        db['baz'] = {'foo': 'bar'}
        for key, item in db.items():
            assert key
            assert item
