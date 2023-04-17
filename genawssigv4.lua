local ffi = require "ffi"
local S = ffi.load("genawssigv4")

ffi.cdef[[
    typedef uint64_t size_t;
    typedef int64_t time_t;

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
    
        const char *url_path;
        size_t url_path_len;

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
]]

local c_buf_type = ffi.typeof("char[?]")

local function generate_aws_sigv4(access_key_id, secret_access_key, region, date_iso8601, method, url_path, query, headers)
    local params = ffi.new("generate_aws_sigv4_params_t[1]")
    params[0].access_key_id = access_key_id
    params[0].access_key_id_len = #access_key_id
    params[0].secret_access_key = secret_access_key
    params[0].secret_access_key_len = #secret_access_key
    params[0].region = region
    params[0].region_len = #region
    params[0].date_iso8601 = date_iso8601
    params[0].method = method
    params[0].method_len = #method
    params[0].url_path = url_path
    if url_path == nil then
        params[0].url_path_len = 0
    else
        params[0].url_path_len = #url_path
    end
    params[0].query = query
    if query == nil then
        params[0].query_len = 0
    else
        params[0].query_len = #query
    end
    params[0].headers = headers
    params[0].headers_len = #headers

    local auth_buf_len = 2048
    params[0].auth_buf = ffi.new(c_buf_type, auth_buf_len)
    params[0].auth_buf_len = auth_buf_len

    local rc = S.generate_aws_sigv4(params[0])
    if rc ~= 0 then
        return nil, "failed to generate signature"
    end
    local authorization = ffi.string(params[0].auth_buf, params[0].auth_buf_len)
    return authorization
end

local function format_iso8601_date(abs_num_time)
    local utc_time = ffi.new("time_t")
    utc_time = math.floor(abs_num_time)

    local date_iso8601_len = 16
    local date_buf = ffi.new(c_buf_type, date_iso8601_len + 1) -- 1 for '\0'
    S.sprint_iso8601_date(date_buf, utc_time)
    return ffi.string(date_buf, date_iso8601_len)
end

return {
    generate_aws_sigv4 = generate_aws_sigv4,
    format_iso8601_date = format_iso8601_date,
}
