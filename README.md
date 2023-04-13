## DjBug

- DjBug is a Django app to trace the server break.
- Detailed documentation is in the "docs" directory.

## Quick start


1. Add "dj_app" to your INSTALLED_APPS setting like this::

		INSTALLED_APPS = [
		    ...
		    'dj_bug',
		]

2. Add **DJBUG_PROJECT_URL** and **DJBUG_API_KEY** variables to your **settings.py**  file.

		DJBUG_PROJECT_URL= "your project URL"
		DJBUG_API_KEY= "your api key"

3. Add **ENVIRONMENT** variable to your settings.py file::

	    ENVIRONMENT = "development" # or "production"

4. Add the **LOGGING** configurations into your settings.py.::

	    LOGGING = {
	        'version': 1,
	        # The version number of our log
	        'disable_existing_loggers': False,
	        'formatters': {
	            "json": {
	                '()': 'dj_bug.formatter.JSONFormatter',
	            },
	            'verbose': {
	                'format': ' Level: {levelname}\n Time: {asctime}\n'
	                          ' Module: {module}\n Location: "{pathname}:{lineno}"\n '
	                          'Exception: {exc_info}\n Message: {message}\n ',
	                'style': '{',
	            },
	            'simple': {
	                'format': '{levelname} {asctime}: {message}',
	                'style': '{',
	            },
	        },
	        'handlers': {
	            'request_handler': {
	                'level': 'WARNING',
	                'class': 'logging.FileHandler',
	                'filename': BASE_DIR / 'error.log',
	                'formatter': 'verbose'
	            },
	            'console': {
	                'level': 'INFO',
	                'class': 'logging.StreamHandler',
	                'formatter': 'simple'
	            },
	            'http_handler': {
	                'level': "ERROR",
	                'class': 'dj_bug.log_handlers.CustomHttpHandler',
	                'url': DJBUG_PROJECT_URL,
	                'token': DJBUG_API_KEY,
	                'formatter': 'json'
	            }
	        },
	        'loggers': {
	            '': {
	                'handlers': ['console'],
	                'level': 'INFO',
	            },
	            'django.request': {
	                'handlers': ['console', 'request_handler', 'http_handler'],
	                'level': 'WARNING',
	                'propagate': False
	            },
	        },
	    }

5. Now run the development server.

	    python manage.py runserver

