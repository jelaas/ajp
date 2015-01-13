ajp [-vh] CMD [[ajp://](FQDN|IP)[:PORT]] [URI]
 -v --verbose          increase verboseness
 -p --port N           port number to use [8009]
 -s --server SERVER_NAME[:PORT]
 -r --remote_addr      client address [127.0.0.100]
    --remote_host      remote host []
    --protocol         protocol [HTTP/1.1]
 -c --count N          number of requests to send
 -H --header NAME=VALUE
 -a --attribute NAME=VALUE
                       Predefined attributes are:
                       context, servlet_path, remote_user,
                       auth_type, query_string, jvm_route,
                       ssl_cert, ssl_cipher, ssl_session
 -S --ssl              Set is_ssl flag

 CMD:
 PING
 GET

Examples:
 ajp ping ajp://ajp.host:8009
 ajp get ajp://ajp.host:8009 http://URL
