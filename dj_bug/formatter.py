import json
import logging
import traceback
from datetime import datetime

from django.conf import settings

BUILTIN_ATTRS = {
    'args',
    'asctime',
    'created',
    'exc_info',
    'exc_text',
    'filename',
    'funcName',
    'levelname',
    'levelno',
    'lineno',
    'module',
    'msecs',
    'message',
    'msg',
    'name',
    'pathname',
    'process',
    'processName',
    'relativeCreated',
    'stack_info',
    'thread',
    'threadName',
}

REQUEST_PARAMETERS = ['SHELL', 'SESSION_MANAGER', 'QT_ACCESSIBILITY',
                      'SNAP_REVISION', 'XDG_CONFIG_DIRS', 'SSH_AGENT_LAUNCHER',
                      'LANGUAGE', 'GNOME_SHELL_SESSION_MODE', 'SSH_AUTH_SOCK',
                      'TERM_SESSION_ID', 'XMODIFIERS', 'DESKTOP_SESSION',
                      'GTK_MODULES', 'PWD', 'XDG_SESSION_DESKTOP', 'LOGNAME',
                      'XDG_SESSION_TYPE', 'GPG_AGENT_INFO', 'SYSTEMD_EXEC_PID',
                      'XAUTHORITY', 'SNAP_CONTEXT', 'GJS_DEBUG_TOPICS',
                      'WINDOWPATH', 'HOME', 'USERNAME', 'IM_CONFIG_PHASE',
                      'LANG', 'LS_COLORS', 'XDG_CURRENT_DESKTOP', 'VIRTUAL_ENV',
                      'INVOCATION_ID', 'MANAGERPID', 'GJS_DEBUG_OUTPUT',
                      'LESSCLOSE', 'XDG_SESSION_CLASS', 'TERM', 'LESSOPEN',
                      'USER', 'SNAP_VERSION', 'DISPLAY', 'SHLVL', 'SNAP_COOKIE',
                      'QT_IM_MODULE', 'VIRTUAL_ENV_PROMPT', 'CONDA_PYTHON_EXE',
                      'XDG_RUNTIME_DIR', 'SNAP_NAME', 'JOURNAL_STREAM',
                      'XDG_DATA_DIRS', 'PATH', 'GDMSESSION',
                      'DBUS_SESSION_BUS_ADDRESS', '_', 'DJANGO_SETTINGS_MODULE',
                      'TZ', 'RUN_MAIN', 'SERVER_NAME', 'GATEWAY_INTERFACE',
                      'SERVER_PORT', 'REMOTE_HOST', 'SERVER_PROTOCOL',
                      'SERVER_SOFTWARE', 'REQUEST_METHOD', 'PATH_INFO',
                      'QUERY_STRING', 'REMOTE_ADDR', 'CONTENT_TYPE',
                      'HTTP_HOST', 'HTTP_CONNECTION', 'HTTP_CACHE_CONTROL',
                      'HTTP_SEC_CH_UA', 'HTTP_SEC_CH_UA_MOBILE',
                      'HTTP_SEC_CH_UA_PLATFORM',
                      'HTTP_UPGRADE_INSECURE_REQUESTS', 'HTTP_USER_AGENT',
                      'HTTP_ACCEPT', 'HTTP_SEC_FETCH_SITE',
                      'HTTP_SEC_FETCH_MODE', 'HTTP_SEC_FETCH_USER',
                      'HTTP_SEC_FETCH_DEST', 'HTTP_ACCEPT_ENCODING',
                      'HTTP_ACCEPT_LANGUAGE', 'HTTP_COOKIE', 'CSRF_COOKIE']


class JSONFormatter(logging.Formatter):
    """JSON log formatter.
    Usage example::
        import logging
        import json_log_formatter
        json_handler = logging.FileHandler(filename='/var/log/my-log.json')
        json_handler.setFormatter(json_log_formatter.JSONFormatter())
        logger = logging.getLogger('my_json')
        logger.addHandler(json_handler)
        logger.info('Sign up', extra={'referral_code': '52d6ce'})
    The log file will contain the following log record (inline)::
        {
            "message": "Sign up",
            "time": "2015-09-01T06:06:26.524448",
            "referral_code": "52d6ce"
        }
    """

    json_lib = json

    def format(self, record):
        message = record.getMessage()
        extra = self.extra_from_record(record)
        frames = traceback.extract_tb(record.exc_info[2], limit=5)

        traceback_list = []
        for frame in frames:
            traceback_content = {'filename': frame.filename,
                                 'lineno': frame.lineno,
                                 'line': frame.line,
                                 'function_name': frame.name}
            traceback_list.append(traceback_content)

        extra['traceback_info'] = traceback_list
        extra['environment'] = settings.ENVIRONMENT
        extra['exception_class'] = record.exc_info[0].__name__
        extra['exception_value'] = record.exc_info[1].args[0]

        if 'request' in extra:
            request = extra.get('request')
            extra['method'] = request.method
            extra['path'] = request.path_info
            if request.user.is_authenticated:
                extra['user'] = request.user.username
                extra['user_id'] = request.user.id
                extra['email'] = request.user.email
            else:
                extra['user'] = "AnonymousUser"
                extra['user_id'] = "-"
                extra['email'] = "-"

            request_dict_data = request.__dict__
            request_meta_info = request_dict_data.get('META')

            request_info = {}
            for i, j in request_meta_info.items():
                if i not in extra and i in REQUEST_PARAMETERS:
                    request_info[i] = j

            extra['request_info'] = request_info
            del extra['request']
        json_record = self.json_record(message, extra, record)
        mutated_record = self.mutate_json_record(json_record)
        # Backwards compatibility: Functions that overwrite this but don't
        # return a new value will return None because they modified the
        # argument passed in.
        if mutated_record is None:
            mutated_record = json_record
        return self.to_json(mutated_record)

    def to_json(self, record):
        """Converts record dict to a JSON string.
        It makes best effort to serialize a record (represents an object as a string)
        instead of raising TypeError if json library supports default argument.
        Note, ujson doesn't support it.
        ValueError and OverflowError are also caught to avoid crashing an app,
        e.g., due to circular reference.
        Override this method to change the way dict is converted to JSON.
        """

        try:
            return self.json_lib.dumps(record, default=_json_serializable)
        # ujson doesn't support default argument and raises TypeError.
        # "ValueError: Circular reference detected" is raised
        # when there is a reference to object inside the object itself.
        except (TypeError, ValueError, OverflowError):
            try:
                return self.json_lib.dumps(record)
            except (TypeError, ValueError, OverflowError):
                return '{}'

    def extra_from_record(self, record):
        """Returns `extra` dict you passed to logger.
        The `extra` keyword argument is used to populate the `__dict__` of
        the `LogRecord`.
        """
        return {
            attr_name: record.__dict__[attr_name]
            for attr_name in record.__dict__
            if attr_name not in BUILTIN_ATTRS
        }

    def json_record(self, message, extra, record):
        """Prepares a JSON payload which will be logged.
        Override this method to change JSON log format.
        :param message: Log message, e.g., `logger.info(msg='Sign up')`.
        :param extra: Dictionary that was passed as `extra` param
            `logger.info('Sign up', extra={'referral_code': '52d6ce'})`.
        :param record: `LogRecord` we got from `JSONFormatter.format()`.
        :return: Dictionary which will be passed to JSON lib.
        """
        extra['message'] = message
        if 'time' not in extra:
            extra['time'] = datetime.utcnow()

        if record.exc_info:
            extra['exc_info'] = self.formatException(record.exc_info)

        return extra

    def mutate_json_record(self, json_record):
        """Override it to convert fields of `json_record` to needed types.
        Default implementation converts `datetime` to string in ISO8601 format.
        """
        for attr_name in json_record:
            attr = json_record[attr_name]
            if isinstance(attr, datetime):
                json_record[attr_name] = attr.isoformat()
        return json_record


def _json_serializable(obj):
    try:
        return obj.__dict__
    except AttributeError:
        return str(obj)


class VerboseJSONFormatter(JSONFormatter):
    """JSON log formatter with built-in log record attributes such as log level.
    Usage example::
        import logging
        import json_log_formatter
        json_handler = logging.FileHandler(filename='/var/log/my-log.json')
        json_handler.setFormatter(json_log_formatter.VerboseJSONFormatter())
        logger = logging.getLogger('my_verbose_json')
        logger.addHandler(json_handler)
        logger.error('An error has occured')
    The log file will contain the following log record (inline)::
        {
            "filename": "tests.py",
            "funcName": "test_file_name_is_testspy",
            "levelname": "ERROR",
            "lineno": 276,
            "module": "tests",
            "name": "my_verbose_json",
            "pathname": "/Users/bob/json-log-formatter/tests.py",
            "process": 3081,
            "processName": "MainProcess",
            "stack_info": null,
            "thread": 4664270272,
            "threadName": "MainThread",
            "message": "An error has occured",
            "time": "2021-07-04T21:05:42.767726"
        }
    Read more about the built-in log record attributes
    https://docs.python.org/3/library/logging.html#logrecord-attributes.
    """

    def json_record(self, message, extra, record):
        extra['filename'] = record.filename
        extra['funcName'] = record.funcName
        extra['levelname'] = record.levelname
        extra['lineno'] = record.lineno
        extra['module'] = record.module
        extra['name'] = record.name
        extra['pathname'] = record.pathname
        extra['process'] = record.process
        extra['processName'] = record.processName
        if hasattr(record, 'stack_info'):
            extra['stack_info'] = record.stack_info
        else:
            extra['stack_info'] = None
        extra['thread'] = record.thread
        extra['threadName'] = record.threadName
        return super(VerboseJSONFormatter, self).json_record(message, extra,
                                                             record)
