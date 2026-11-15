"""HTTP 请求工具."""

import requests


def http_post(url: str, json_data: dict = None, headers: dict = None,
              timeout: int = 30, verify: bool = False) -> requests.Response:
    return requests.post(url, json=json_data, headers=headers or {},
                         timeout=timeout, verify=verify)


def http_get(url: str, params: dict = None, headers: dict = None,
             timeout: int = 30, verify: bool = False) -> requests.Response:
    return requests.get(url, params=params, headers=headers or {},
                        timeout=timeout, verify=verify)
