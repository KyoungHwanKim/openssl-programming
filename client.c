#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define bufsize 1024

void init_ssl() {
    SSL_load_error_strings();
    SSL_library_init();
}

void report_and_exit(const char* msg) {
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void secure_connect(const char* host);

int main() {
    init_ssl();

    const char* hostname = "www.google.com";
    fprintf(stderr, "Trying an HTTPS connection to %s...\n", hostname);
    secure_connect(hostname);

    return 0;
}

void cleanup(SSL_CTX* ctx, BIO* bio) {
    SSL_CTX_free(ctx);
    BIO_free_all(bio);
}

void secure_connect(const char* host) {
    char name[bufsize];
    char request[bufsize];
    char response[bufsize];

    const SSL_METHOD* method = TLSv1_2_client_method();
    if (method == NULL) report_and_exit("TLSv1_2_client_method...");

    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx == NULL) report_and_exit("SSL_CTX_new...");

    BIO* bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) report_and_exit("BIO_new_ssl_connect...");

    SSL* ssl = NULL;

    sprintf(name, "%s:%s", host, "https");
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, name);

    if (BIO_do_connect(bio) <= 0) {
        cleanup(ctx, bio);
        report_and_exit("BIO_do_connect...");
    }

    if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/")) {
        report_and_exit("SSL_CTX_load_verify_locations...");
    }

    long verify_flag = SSL_get_verify_result(ssl);
    if (verify_flag != X509_V_OK) {
        fprintf(stderr, "#### Certificate verification error (%i) but continuing...\n", (int) verify_flag);
    }

    sprintf(request, "GET / HTTP/1.1\x0D\x0AHost: %s\x0D\x0A\x43onnection: Close\x0D\x0A\x0D\x0A", host);
    BIO_puts(bio, request);

    while (1) {
        memset(response, '\0', sizeof(response));
        int n = BIO_read(bio, response, bufsize);
        if (n <= 0) break;
        puts(response);
    }

    cleanup(ctx, bio);

}