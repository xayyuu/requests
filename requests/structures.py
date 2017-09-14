# -*- coding: utf-8 -*-

"""
requests.structures
~~~~~~~~~~~~~~~~~~~

Datastructures that power Requests.

"""

from UserDict import DictMixin


class CaseInsensitiveDict(DictMixin):  # 将输入转换成字典，并赋予输入以字典形式进行处理。
    """docstring for CaseInsensitiveDict"""

    def __init__(self, *args, **kwargs):
        # super(CaseInsensitiveDict, self).__init__()
        self.data = dict(*args, **kwargs)  # dict(one=1, two=2)，之所以这样，是因为reqeusts接口都是reqeusts=这种关键字。*, **参数的区别。

    def __repr__(self):
        return self.data.__repr__()

    def __getstate__(self):  # 序列化pickle时使用。
        return self.data.copy()

    def __setstate__(self, d):
        self.data = d

    def _lower_keys(self):
        return map(str.lower, self.data.keys())  # map(func, iter) == func(iter) for i in iter), str.lower不是应该是类的方法吗？ 可以直接调用码？


    def __contains__(self, key):  # 重载 in 操作符
        return key.lower() in self._lower_keys()


    def __getitem__(self, key):

        if key.lower() in self:
            return self.items()[self._lower_keys().index(key.lower())][1]  # 有序的类型，就有index这个接口查找下标。

    def __setitem__(self, key, value):
        return self.data.__setitem__(key, value)


    def __delitem__(self, key):
        return self.data.__delitem__(key)


    def __keys__(self):
        return self.data.__keys__()


    def __iter__(self):
        return self.data.__iter__()


    def iteritems(self):
        return self.data.iteritems()
