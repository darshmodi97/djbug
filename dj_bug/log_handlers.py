import logging

import requests
from django.http import HttpResponse
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


class CustomHttpHandler(logging.Handler):
    def __init__(self, url: str, token: str, silent: bool = True):
        '''
        Initializes the custom http handler
        Parameters:
            url (str): The URL that the logs will be sent to
            token (str): The Authorization token being used
            silent (bool): If False the http response and logs will be sent
                           to STDOUT for debug
        '''
        self.url = url
        self.token = token
        self.silent = silent

        # sets up a session with the server
        self.MAX_POOLSIZE = 100
        self.session = session = requests.Session()
        session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': self.token
        })

        self.session.mount('http://', HTTPAdapter(
            max_retries=Retry(
                total=5,
                backoff_factor=0.5,
                status_forcelist=[403, 500]
            ),
            pool_connections=self.MAX_POOLSIZE,
            pool_maxsize=self.MAX_POOLSIZE
        ))

        super().__init__()

    def emit(self, record):
        '''
        This function gets called when a log event gets emitted. It recieves a
        record, formats it and sends it to the url
        Parameters:
            record: a log record
        '''
        log_data = self.format(record)
        response = self.session.post(self.url, data=log_data)
        if response.status_code != 200:
            return HttpResponse(response.text)
        if not self.silent:
            print(log_data)
            print(response.content)
