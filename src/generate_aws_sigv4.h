#ifndef GENERATE_AWS_SIGV4_H_
#define GENERATE_AWS_SIGV4_H_

#include <stddef.h>
#include <time.h>

typedef struct {
    /* input parameters */

    const char *access_key_id;
    size_t access_key_id_len;

    const char *secret_access_key;
    size_t secret_access_key_len;

    const char *region;
    size_t region_len;

    const char *date_iso8601; /* YYYYmmddTHHMMSSZ */

    const char *method;
    size_t method_len;

    const char *escaped_url_path;
    size_t escaped_url_path_len;

    const char *query;
    size_t query_len;

    const char *headers;
    size_t headers_len;

    /* output parameters */

    char *auth_buf; /* caller must provide memory (ex. 2048 bytes). */
    size_t auth_buf_len;

    char *signature; /* points to somewhere in auth_buf. */
    size_t signature_len;

} generate_aws_sigv4_params_t;

int generate_aws_sigv4(generate_aws_sigv4_params_t *param);

/* caller must provide memory for out with 17 bytes (YYYYmmddTHHMMSSZ + '\0') */
void sprint_iso8601_date(char *out, time_t utc_time);

size_t escape_uri_path(const unsigned char *src, size_t src_len,
                       char *dst, size_t dest_len);

#endif /* ifndef GENERATE_AWS_SIGV4_H_ */
