from pyop.storage import MongoWrapper


class DocumentDoesNotExist(Exception):
    pass


class OpStorageWrapper(MongoWrapper):
    def __init__(self, db_uri, collection):
        super().__init__(db_uri, 'seleg_op', collection)

    def get_documents_by_attr(self, attr, value, raise_on_missing=True):
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :type attr: str
        :param value: The field value
        :type value: str
        :param raise_on_missing:  If True, raise exception if no matching document can be found.
        :type raise_on_missing: bool
        :return: A tuple of lookup_key, data
        :rtype: tuple
        :raise DocumentDoesNotExist: No document matching the search criteria
        """
        docs = self._coll.find({attr: value})
        if docs.count() == 0 and raise_on_missing:
            raise DocumentDoesNotExist("No document matching %s='%s'" % (attr, value))
        for doc in docs:
            yield (doc['lookup_key'], doc['data'])

    def get_documents_by_filter(self, spec, fields=None, raise_on_missing=True):
        """
        Locate a documents in the db using a custom search filter.

        :param spec: the search filter
        :type spec: dict
        :param fields: the fields to return in the search result
        :type fields: dict
        :param raise_on_missing:  If True, raise exception if no matching document can be found.
        :type raise_on_missing: bool
        :return: A document dict
        :rtype: cursor | []
        :raise DocumentDoesNotExist: No document matching the search criteria
        """
        if fields is None:
            docs = self._coll.find(spec)
        else:
            docs = self._coll.find(spec, fields)
        if docs.count() == 0 and raise_on_missing:
            raise DocumentDoesNotExist('No document matching {!s}'.format(spec))
        for doc in docs:
            yield (doc['lookup_key'], doc['data'])
