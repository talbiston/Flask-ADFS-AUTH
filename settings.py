# checkout the documentation for more settings
AUTH_ADFS = {
    "SERVER": "adfs.gtt.net",
    "CLIENT_ID": "38295e7f-e26c-4609-b31b-b4c042f32f01",
    "RELYING_PARTY_ID": "38295e7f-e26c-4609-b31b-b4c042f32f01",
    # Make sure to read the documentation about the AUDIENCE setting
    # when you configured the identifier as a URL!
    "AUDIENCE": "microsoft:identityserver:38295e7f-e26c-4609-b31b-b4c042f32f01",
    #"CA_BUNDLE": "/path/to/ca-bundle.pem",s
    "CLAIM_MAPPING": {"first_name": "given_name",
                      "last_name": "family_name",
                      "email": "email"
                      },
    "USERNAME_CLAIM": "winaccountname",
    "GROUP_CLAIM": None
                    
    }

# Configure django to redirect users to the right URL for login
LOGIN_URL = "django_auth_adfs:login"
LOGIN_REDIRECT_URL = "/"
#LOGIN_REDIRECT_URL = "https://opengdev.build.gtt.net/oauth2/callback"