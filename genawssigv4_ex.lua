local genawssigv4 = require "genawssigv4"

print(string.format("escaped path=[%s]", genawssigv4.uri_encode_path("/aA0-._~!$&'()*+,;=:@/\t%日")))
print(string.format("escaped query_key=[%s]", genawssigv4.uri_encode_query_key_or_val("/aA0-._~!$&'()*+,;=:@/\t%日")))
print(string.format("percent decoded=[%s]", genawssigv4.percent_decode("a+b%20c")))

local date_iso8601 = genawssigv4.format_iso8601_date(os.time())
local access_key_id = 'foo'
local secret_access_key = 'bar'
local region = 'jp-north-1'
local method = 'GET'
local encoded_url_path = genawssigv4.uri_encode_path("/日本語/ですね.txt")
local encoded_query = ''
local header_fields = {
    'host:example.com',
    'x-amz-content-sha256:UNSIGNED-PAYLOAD',
    'x-amz-date:' .. date_iso8601,
}
local headers = table.concat(header_fields, '\r\n') .. '\r\n'

local signature = genawssigv4.generate_aws_sigv4(access_key_id, secret_access_key, region, date_iso8601, method, encoded_url_path, encoded_query, headers)
print(string.format("signature=[%s]", signature))
