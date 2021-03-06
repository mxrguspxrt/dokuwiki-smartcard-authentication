# Installation


## Preconditions

1. You have configured your Apache as follows:

```
<VirtualHost IP:443> 
  ...
  # this is under virtualhost :443 section
  # your webserver public and private cert
  SSLCertificateFile    /etc/ssl/certs/www.domain.ee.crt
  SSLCertificateKeyFile /etc/ssl/private/www.domain.ee.key
  # This makes certain, that its valid smartcard and is allowed (google for ID kaart + apache server)
  SSLCACertificateFile /etc/ssl/certs/id.crt
  ...
</VirtualHost>
```

If you want that before opening Wiki user certificate is asked and autolog is done, add also these lines to your Virtualhost config or .htaccess file in Wiki root:

```
# request client cert
SSLVerifyClient require
SSLVerifyDepth 2
SSLOptions +StdEnvVars +ExportCertData
```

2. Using .htaccess must be allowed. If it is not allowed, you have to copy inc/auth/smartcard/.htaccess content to virtualhost directory section for inc/auth/smartcard:

```
<VirtualHost IP:443>
  ...
  # Usally using Directory instead of Location is recommended, 
  # but this is not for security, but for asking certificate
  <Location "/inc/auth/smartcard">
    SSLVerifyClient Optional
    SSLVerifyDepth 2
    SSLOptions +StdEnvVars +ExportCertData
  </Location>
...
</VirtualHost>
```



3. If your value against what your would like to check is not in certificate.subject.serialNumber, you will have to change `inc/auth/smartcard.php` line 85.

## Steps

- cd your_dokuwiki_folder
- svn export https://dokuwiki-smartcard-authentication.googlecode.com/svn/trunk/dokuwiki/ . --force
- Configure authentication module (See: "Configure parameters")
- Make Smartcard autentication available for user
  - Add to your wiki what would reference to https://YOUR_DOMAIN/DOKUWIKI_PATH/inc/auth/smartcard
  - Modify in YOUR_DOKUWIKI_INSTALLATION/inc/lang/YOUR_CHOSEN_LANGUAGE/login.txt and add line: `To log in with smart card, click: [[inc/auth/smartcard|Autenticate me with Smartcard]]`
- Clear your Dokuwiki cache 



## Allowing Smartcard authentication

You have to do:
- Mark user serial (or some other parameter for check) as one of his groups.

This auth module will authenticated user based on the serial found on smartcard with steps:

- If ?u=smartcard&p=smartcard is called script check that `certificate.subject.serialNumber` exists (from `$_SERVER['SSL_CLIENT_S_DN'`)
  - if it exists: user, who has this value as his group, is allowed in
  - if it does not exist: user is not allowed in
- If auth is called with other parameters and `$conf['smartcard']['allow_without_smartcard']` is checked
  - if it is `true`: auth is delegated to auth modules defined in `$conf['smartcard']['use_authtypes']`
  - else login with username and password will not be possible.


## Configuration

Must be defined in file: YOUR_WIKI_INSTALLATION/conf/local.php.

Config parameters explanation:

```php
# set for docuwiki that smartcard auth module is used
$conf['authtype']   = 'smartcard';

# if this is set to true, without smartcard login is not allowed
$conf['auth']['smartcard']['allow_without_smartcard'] = 'true';

# auth modules to use. separated with comma (",")
$conf['auth']['smartcard']['use_authtypes'] = 'plain,mysql';

# log debug info to file
$conf['auth']['smartcard']['log_to_file'] = 'true';
```


# Known problems

- When using Fckglite WYSIWYG editor, first login fails - because fckglite resets session - fix info: http://code.google.com/p/dokuwiki-smartcard-authentication/issues/detail?id=1


# Author

Margus Pärt (mxrguspxrt)
