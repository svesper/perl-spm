# perl-spm
Perl SCGI application server "Perl-SPM" (SCGI Process Manager)

Perl-SPM is an application server to simply and fast execute your perl scripts in combination with a web server like Apache or Nginx on Linux via SCGI.

Perl-SPM uses Simple Common Gateway Interface (SCGI) to connect to web servers which is similar to FastCGI but simpler designed.
Perl-SPM tries to be as useful as PHP-FPM (FastCGI Process Manager) is for PHP and was created in analogy to PHP-FPM development and deployment philosophie.

# SCGI
SCGI offers excellent performance and simplicity. There are no protocoll features like connection multiplexing which increase software complexity unnecessary. Instead you get stability and simplicity as a tradeoff for rarley used features. 
Also take a look at the modern Perl Web Server Gateway Interface (PSGI) in comparison. 

# Perl + SCGI
Perl and SCGI perfectly fit together in an preforking server design, because child processes can be terminated after each request which leads to a very simple and performant memory management. 

# Installation
Just copy the main "perl-spm.pl" file on your system and copy the INIT script "perl-spm" under to "/etc/init.d/" (do not forget to adjust the path to "perl-spm.pl" inside the INIT-script). On its first launch it will create a log file under "/var/log/perl-spm.log" and adjust file privileges to the configured system user.

# Configuration
At the beginning of the "perl-spm.pl" file you can configure the unprivileged user via RUN_USER and RUN_GROUP normally "www-data" together with some other variables like total process to spawn, ports and so on. The defaults values should be fine to start with.

Apache configuration:

Remember, in order to make the following examples work, you have to enable mod_proxy and mod_proxy_scgi.
https://httpd.apache.org/docs/2.4/mod/mod_proxy_scgi.html

```javascript
# global apache config options for all files ending with ".pl"
ProxyPassMatch ^/.*\.pl$ "scgi://127.0.0.1:9004/"

OR

# Simple SCGI gateway under "/scgi/" URL-path:
ProxyPass "/scgi/" "scgi://localhost:9004/"

OR

# as a directory config ( https://httpd.apache.org/docs/2.4/mod/core.html#sethandler )
<Directory "/var/www/apache/scgi/">
        DirectoryIndex index.cgi index.pl
        #SetHandler  "proxy:unix:/path/to/app.sock|fcgi://localhost/"
        <FilesMatch "\.(pl|cgi)$">
                SetHandler  "proxy:scgi://localhost:9004/"
        </FilesMatch>
</Directory>

OR

# as a location match config
<LocationMatch "^/loc_scgi/.*\.cgi$">
        DirectoryIndex index.cgi
        ProxyPassMatch "scgi://127.0.0.1:9004/"
</LocationMatch>



```

Nginx configuration:
```javascript
## add this SCRIPT_NAME parameter in your configuration section or in "scgi_params" config file
## otherwise perl-spm can not determine file location
# scgi_param      SCRIPT_FILENAME    $request_filename;
# scgi_param      SCRIPT_NAME        $fastcgi_script_name;

# add a perl-spm upstream server to your nginx configuration
upstream perl-spm {
     server   127.0.0.1:9004;
}

# match by file-ending
location ~* \.(cgi|pl)$ {
        gzip           off;
        fastcgi_index  index.cgi;
        try_files $uri =404;
                
        scgi_pass       perl-spm;
        include         scgi_params;
        scgi_param      SCRIPT_FILENAME    $request_filename;
        scgi_param      SCRIPT_NAME        $fastcgi_script_name;
}

OR 

# match by URL-path
location ~ /perl-spm/ {
        http2_push_preload on;
        client_max_body_size 1g;
               
        fastcgi_index  index.cgi;
        try_files $uri =404;
        scgi_pass       perl-spm;
        include         scgi_params;
        scgi_param      SCRIPT_FILENAME    $request_filename;
        scgi_param      SCRIPT_NAME        $fastcgi_script_name;
}



```

# Start perl-spm
You can run the perl-spm.pl file directly but i would suggest using the INIT-script "/etc/init.d/perl-spm start". 

If you run the "perl-spm.pl" from command line, you have to initially execute it by root for automatic creation of the logfile under "/var/log/perl-spm.log".
After that you can also start it as unprivileged user, it will drop privileges and change to the configured RUN_USER. 

Enjoy! :-)
