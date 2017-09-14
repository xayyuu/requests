# -*- coding: utf-8 -*-

"""
requests.api
~~~~~~~~~~~~

This module impliments the Requests API.

:copyright: (c) 2011 by Kenneth Reitz.
:license: ISC, see LICENSE for more details.

"""

import requests
from .models import Request, Response, AuthManager, AuthObject, auth_manager


__all__ = ('request', 'get', 'head', 'post', 'put', 'delete')  # __all__ 用法，再core.py中有调用from api.py import *，通过__all__控制引入命名空间。



# 封装接口的思想，值得学习。request比较出彩的地方之一，在于接口设计的足够简洁清晰。
# 如果没有get, head, post put delete等接口，将会怎么调用呢？
#  调用方法将会是这样的：
#          r = requests.request('http://www.google.com/search', params={'q': 'test'}, headers=heads) 意义不明。
#  加入没有 request， 调用方法将会是：
#  r = Request(.....)
#  r.send()  # 将会有很多重复代码，并且缺少data的检查。
# 所以封装接口，第一要提供意义明确的接口，第二要减少调用时的重复代码。
# **kwargs 也不错。

def request(method, url, **kwargs):
    """Sends a `method` request. Returns :class:`Response` object.

    :param method: method for the new :class:`Request` object.
    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of GET/HEAD/DELETE Parameters to send with the :class:`Request`.
    :param data: (optional) Bytes/Dictionary of PUT/POST Data to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    """
    data = kwargs.pop('data', dict()) or kwargs.pop('params', dict())  # 不错的用法。处理异常了。

    r = Request(method=method, url=url, data=data, headers=kwargs.pop('headers', {}),
                cookiejar=kwargs.pop('cookies', None), files=kwargs.pop('files', None),
                auth=kwargs.pop('auth', auth_manager.get_auth(url)),
                timeout=kwargs.pop('timeout', requests.timeout))
    r.send()

    return r.response


def get(url, params={}, headers={}, cookies=None, auth=None, **kwargs):
    """Sends a GET request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of GET Parameters to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to send with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    """

    return request('GET', url, params=params, headers=headers, cookies=cookies, auth=auth, **kwargs)


def head(url, params={}, headers={}, cookies=None, auth=None, **kwargs):
    """Sends a HEAD request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of GET Parameters to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    """

    return request('HEAD', url, params=params, headers=headers, cookies=cookies, auth=auth, **kwargs)


def post(url, data={}, headers={}, files=None, cookies=None, auth=None, **kwargs):
    """Sends a POST request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param data: (optional) Dictionary of POST data to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    """

    return request('POST', url, data=data, headers=headers, files=files, cookies=cookies, auth=auth, **kwargs)


def put(url, data='', headers={}, files={}, cookies=None, auth=None, **kwargs):
    """Sends a PUT request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Bytes of PUT Data to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param files: (optional) Dictionary of 'filename': file-like-objects for multipart encoding upload.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    """

    return request('PUT', url, data=data, headers=headers, files=files, cookies=cookies, auth=auth, **kwargs)


def delete(url, params={}, headers={}, cookies=None, auth=None, **kwargs):
    """Sends a DELETE request. Returns :class:`Response` object.

    :param url: URL for the new :class:`Request` object.
    :param params: (optional) Dictionary of DELETE Parameters to send with the :class:`Request`.
    :param headers: (optional) Dictionary of HTTP Headers to sent with the :class:`Request`.
    :param cookies: (optional) CookieJar object to send with the :class:`Request`.
    :param auth: (optional) AuthObject to enable Basic HTTP Auth.
    :param timeout: (optional) Float describing the timeout of the request.
    """

    return request('DELETE', url, params=params, headers=headers, cookies=cookies, auth=auth, **kwargs)
