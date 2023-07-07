#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <time.h>

#include "generate_aws_sigv4.h"
#include "sigv4.h"

/**
 * @brief AWS Service name to send HTTP request using SigV4 library.
 */
#define AWS_S3_SERVICE_NAME "s3"

/**
 * @brief Represents empty payload for HTTP GET request sent to AWS S3.
 */
#define S3_REQUEST_EMPTY_PAYLOAD ""

/**
 * @brief Length in bytes of hex encoded hash digest.
 */
#define HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH ((uint16_t)64)

/**
 * @brief Length in bytes of SHA256 hash digest.
 */
#define SHA256_HASH_DIGEST_LENGTH (HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH / 2)

static int32_t sha256Init(void *hashContext)
{
    crypto_hash_sha256_state *state = (crypto_hash_sha256_state *)hashContext;
    return (int32_t)crypto_hash_sha256_init(state);
}

static int32_t sha256Update(void *hashContext, const uint8_t *pInput,
                            size_t inputLen)
{
    crypto_hash_sha256_state *state = (crypto_hash_sha256_state *)hashContext;
    return crypto_hash_sha256_update(state, pInput, inputLen);
}

static int32_t sha256Final(void *hashContext, uint8_t *pOutput,
                           size_t outputLen)
{
    assert(outputLen >= SHA256_HASH_DIGEST_LENGTH);

    (void)outputLen;

    crypto_hash_sha256_state *state = (crypto_hash_sha256_state *)hashContext;
    return crypto_hash_sha256_final(state, pOutput);
}

int generate_aws_sigv4(generate_aws_sigv4_params_t *param)
{
    SigV4Credentials_t sigvCreds = {
        .pAccessKeyId = param->access_key_id,
        .accessKeyIdLen = param->access_key_id_len,
        .pSecretAccessKey = param->secret_access_key,
        .secretAccessKeyLen = param->secret_access_key_len,
    };

    crypto_hash_sha256_state hashContext;
    SigV4CryptoInterface_t cryptoInterface = {
        .hashInit = sha256Init,
        .hashUpdate = sha256Update,
        .hashFinal = sha256Final,
        .pHashContext = &hashContext,
        .hashBlockLen = HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH,
        .hashDigestLen = SHA256_HASH_DIGEST_LENGTH,
    };

    /* Setup the HTTP parameters. */
    SigV4HttpParameters_t sigv4HttpParams = {
        .pHttpMethod = param->method,
        .httpMethodLen = param->method_len,
        /* None of the requests parameters below are pre-canonicalized */
        .flags = SIGV4_HTTP_PATH_IS_CANONICAL_FLAG | SIGV4_HTTP_PAYLOAD_IS_HASH,
        .pPath = param->escaped_url_path,
        .pathLen = param->escaped_url_path_len,
        /* AWS S3 request does not require any Query parameters. */
        .pQuery = param->query,
        .queryLen = param->query_len,
        .pHeaders = param->headers,
        .headersLen = param->headers_len,
        .pPayload = S3_REQUEST_EMPTY_PAYLOAD,
        .payloadLen = sizeof(S3_REQUEST_EMPTY_PAYLOAD) - 1,
    };

    SigV4Parameters_t sigv4Params = {
        .pCredentials = &sigvCreds,
        .pDateIso8601 = param->date_iso8601,
        .pRegion = param->region,
        .regionLen = param->region_len,
        .pService = AWS_S3_SERVICE_NAME,
        .serviceLen = sizeof(AWS_S3_SERVICE_NAME) - 1,
        .pCryptoInterface = &cryptoInterface,
        .pHttpParameters = &sigv4HttpParams,
    };

    SigV4Status_t sigv4Status = SigV4_GenerateHTTPAuthorization(
        &sigv4Params, param->auth_buf, &param->auth_buf_len, &param->signature,
        &param->signature_len);
    return sigv4Status != SigV4Success;
}

void sprint_iso8601_date(char *out, time_t utc_time)
{
    struct tm tm, *p;

    p = gmtime_r(&utc_time, &tm);
    snprintf(out, sizeof("YYYYmmDDTHHMMSSZ"), "%04d%02d%02dT%02d%02d%02dZ",
             1900 + p->tm_year, p->tm_mon + 1, p->tm_mday, p->tm_hour, p->tm_min,
             p->tm_sec);
}

static int should_escape(unsigned char c)
{
    /*
     * path-absolute = "/" [ segment-nz *( "/" segment ) ]
     * segment       = *pchar
     * segment-nz    = 1*pchar
     * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
     *
     * https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
     */
    if (c == '/' ||
        /*
         * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
         */
        ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
        (c == '-' || c == '.' || c == '_' || c == '~') ||
        /*
         * sub-delims = "!" / "$" / "&" / "'" / "(" / ")"
         *            / "*" / "+" / "," / ";" / "="
         */
        c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' ||
        c == '*' || c == '+' || c == ',' || c == ';' || c == '=' ||
        /*
         * ":" / "@"
         */
        c == ':' || c == '@')
    {
        return 0;
    }
    return 1;
}

size_t escape_uri_path(const unsigned char *src, size_t src_len,
                       char *dst, size_t dst_len)
{
    static const char upper_hex_digits[] = "0123456789ABCDEF";
    size_t i, j;

    i = 0;
    j = 0;
    for (i = 0; i < src_len; i++) {
        if (should_escape(src[i])) {
            if (j < dst_len) {
                dst[j] = '%';
            }
            j++;

            if (j < dst_len) {
                dst[j] = upper_hex_digits[src[i] >> 4];
            }
            j++;

            if (j < dst_len) {
                dst[j] = upper_hex_digits[src[i] & 0x0F];
            }
            j++;
        } else {
            if (j < dst_len) {
                dst[j] = src[i];
            }
            j++;
        }
    }
    return j;
}
