# Install OS and build environment
FROM debian:bullseye-20200224-slim

MAINTAINER Yadwinder Grewal <ygrewal@gmail.com>

RUN apt update && apt -y upgrade
RUN apt -y install \
	make g++ git

# Customize and install nginx
RUN git clone https://grewal:napkauf26@bitbucket.org/grewal/grewal.git
WORKDIR grewal/third_party/nginx/stable/nginx-1.16.1
RUN ./configure --build=grewal_DOCKER \
		--conf-path=conf/nginx_http.conf \
                --without-http_charset_module \
                --without-http_gzip_module \
                --without-http_ssi_module \
                --without-http_userid_module \
                --without-http_access_module \
                --without-http_auth_basic_module \
                --without-http_mirror_module \
                --without-http_autoindex_module \
                --without-http_geo_module \
                --without-http_map_module \
                --without-http_split_clients_module \
                --without-http_referer_module \
                --without-http_rewrite_module \
                --without-http_proxy_module \
                --without-http_uwsgi_module \
                --without-http_scgi_module \
                --without-http_grpc_module \
                --without-http_memcached_module \
                --without-http_limit_conn_module \
                --without-http_limit_req_module \
                --without-http_empty_gif_module \
                --without-http_browser_module \
                --without-http_upstream_hash_module \
                --without-http_upstream_ip_hash_module \
                --without-http_upstream_least_conn_module \
                --without-http_upstream_random_module \
                --without-http_upstream_keepalive_module \
                --without-http_upstream_zone_module \
                --without-mail_pop3_module \
                --without-mail_imap_module \
                --without-mail_smtp_module \
                --without-stream_limit_conn_module \
                --without-stream_access_module \
                --without-stream_geo_module \
                --without-stream_map_module \
                --without-stream_split_clients_module \
                --without-stream_return_module \
                --without-stream_upstream_hash_module \
                --without-stream_upstream_least_conn_module \
                --without-stream_upstream_random_module \
                --without-stream_upstream_zone_module \
                --without-pcre
RUN make
RUN make install

# Remove build binaries
RUN apt -y remove g++ make git
RUN apt -y autoremove
RUN apt -y autoclean

# Open web port 80
EXPOSE 80

# Run the grewal http server & link grewal binary to fcgi server @port :8000
CMD /usr/local/nginx/sbin/nginx -V && /usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx_http.conf
