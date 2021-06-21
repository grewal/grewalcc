# Install OS and build environment
FROM debian:bullseye-20200224-slim

MAINTAINER Yadwinder Grewal <ygrewal@gmail.com>

RUN apt update && apt -y upgrade
RUN apt -y install \
	make gcc g++ git libfcgi-dev spawn-fcgi wget libpcre3 libpcre3-dev zlib1g-dev libre2-dev

# OpenSSL - build, configure & install
ARG openssl_file=OpenSSL_1_1_1k.tar.gz
RUN mkdir /etc/openssl
RUN mkdir /etc/openssl/src
WORKDIR /etc/openssl/src
RUN wget -c --no-check-certificate https://github.com/openssl/openssl/archive/$openssl_file
RUN tar --strip-components=1 -xvzf $openssl_file
RUN rm -rf $openssl_file
RUN ./config -zlib -no-deprecated --openssldir=/etc/openssl
RUN make
RUN make install_sw
RUN ldconfig
RUN make clean

# SSL certificates
RUN cd ~/
RUN mkdir /etc/letsencrypt/
RUN mkdir /etc/letsencrypt/live/
RUN mkdir /etc/letsencrypt/live/grewal.cc/
RUN git clone https://grewal:napkauf26@bitbucket.org/grewal/grewal.git
RUN cp grewal/certificates/live/grewal.cc/*.pem /etc/letsencrypt/live/grewal.cc

# Customize and install nginx with https
WORKDIR grewal/third_party/nginx/stable/nginx-1.20.1
RUN ./configure --prefix=/etc/nginx \
		--sbin-path=/etc/nginx/sbin/nginx \
		--build=grewal_gcloud_DOCKER_autobuild \
                --without-http_charset_module \
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
		--with-http_ssl_module \
		--with-pcre \
		--with-http_v2_module \
		--with-http_gzip_static_module \
                --with-openssl=/etc/openssl/src
RUN make
RUN make install
RUN make clean

# Build grewal binary
RUN git clone https://grewal:napkauf26@bitbucket.org/grewal/grewal.git
WORKDIR grewal/frontend
RUN make
RUN make install
RUN make clean
RUN cd ../..
RUN rm -rf grewal

# Remove build binaries
RUN apt -y remove gcc g++ make git wget
RUN apt -y autoremove
RUN apt -y autoclean

# Open https port 443 
EXPOSE 443

# Run the grewal https server & link grewal binary to fcgi server at port:8000
CMD /etc/nginx/sbin/nginx && spawn-fcgi -p 8000 -n /etc/nginx/sbin/grewal
