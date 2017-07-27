PASSWORD_LINK = "http://202.141.80.24/cgi-bin/chpasswd.cgi"


def change_pass(username, old_pass, new_pass, use_prepared=True):
    """
    Change IITG proxy credentials of a user.



    A note on why this doesn't work always:
    Why does server returns error 500 so frequently?

    The sever expects request body to be in following orders:
    user=username&old_pw=old_pass&new_pw1=new_pass&new_pw2=new_pass&change=Change%2BMy%2BPassword
    user=username&old_pw=old_pass&new_pw2=new_pass&new_pw1=new_pass&change=Change%2BMy%2BPassword

    Any deviation from this order will result in some kind of error.
    For example:
        old_pw=old_pass&user=user&new_pw2=new_pass&new_pw1=new_pass&change=Change%2BMy%2BPassword
    would return 200 OK (User: old_pass not found) response.

    It seems server is considering first param as username, second param as
    old password, and third and fourth as new passwords without checking
    for param name.

    requests takes POST data as a dictionary and Python (< 3.6) doesn't
    respect order of elements in dictionary.

    requests pops (key, value) pairs out of dict and creates response body.
    This popping order isn't fixed. This leads to frequent 500 server errors.
    """
    try:
        import requests
    except ImportError:
        print("requests must be installed for password change.")
        return None

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0"
    }
    data_dict = {
        "change": "Change+My+Password",
        "new_pw1": new_pass,
        "new_pw2": new_pass,
        "old_pw": old_pass,
        "user": username
    }
    if use_prepared:

        req = requests.Request('POST', PASSWORD_LINK, headers=headers, data=data_dict)
        prepared = req.prepare()
        body_str = 'user={0}&old_pw={1}&new_pw1={2}&new_pw2={2}&change=Change%2BMy%2BPassword'.format(
            username, old_pass, new_pass
        )
        prepared.body = body_str

        s = requests.Session()
        s.proxies = {}
        response = s.send(prepared, stream=True, cert=None, verify=True, allow_redirects=False)
    else:
        # Use requests.request()
        # this method often fails.
        # changing credentials manually is better than using
        # following method.
        requests_kwargs = {
            "allow_redirects": False,
            "auth": None,
            "cert": None,
            "data": data_dict,
            "files": {},
            "headers": headers,
            "method": "post",
            "params": {},
            "proxies": {},
            "stream": True,
            "timeout": 30,
            "url": "http://202.141.80.24/cgi-bin/chpasswd.cgi",
            "verify": True
        }
        response = requests.request(**requests_kwargs)
    return response
