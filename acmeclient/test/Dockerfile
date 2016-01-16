# A Dockerfile for the acmeclient_test. It has an Apache server to run
# the apachesolver and copied the built acmeclient program from the host.

FROM httpd:2.4

MAINTAINER Tommie Gannert <tommie@gannert.se>

# Configure apachesolver.
ENV ACME_SOLVER_HTTP_PORT=80
ENV ACME_SOLVER_HTTPS_PORT=443
ENV ACME_CHALLENGE_DIR=/usr/local/apache2/htdocs/.well-known/acme-challenge
ENV ACME_CONFIG_FILE=/usr/local/apache2/conf/extra/httpd-acmeclient.conf
ENV ACME_APACHE2CTL=apache2ctl

EXPOSE $ACME_SOLVER_HTTP_PORT
EXPOSE $ACME_SOLVER_HTTPS_PORT

RUN apt-get update && apt-get install -y openssl
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# All programs we need.
COPY acmeclient/acmeclient /usr/local/bin/acmeclient
COPY acmeclient/acmeclient_test /usr/local/bin/acmeclient_test
COPY solver/apachesolver /usr/local/bin/apachesolver

# http-01
RUN mkdir -p $ACME_CHALLENGE_DIR
RUN sed -i -e '/^Listen 80\$/ d' /usr/local/apache2/conf/httpd.conf

# tls-sni-01
COPY ./acmeclient/test/httpd-apachesolver.conf /usr/local/apache2/conf/extra/httpd-vhosts.conf
RUN touch $ACME_CONFIG_FILE
