local genawssigv4 = require "genawssigv4"

local function add_aws_sigv4_authorization(ts, access_key_id, secret_access_key, region)
    local date_iso8601 = genawssigv4.format_iso8601_date(ts.now())
    ts.server_request.header["x-amz-date"] = date_iso8601
    ts.server_request.header["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"

    local target_header_names = {"host", "x-amz-content-sha256", "x-amz-date"}
    local hdr_fields = {}
    for _, h in ipairs(target_header_names) do
        table.insert(hdr_fields, string.format("%s:%s", h, ts.server_request.header[h]))
    end
    local headers = table.concat(hdr_fields, "\r\n") .. "\r\n"

    local method = ts.server_request.get_method()
    local url_path = ts.server_request.get_uri()
    local query = ts.server_request.get_uri_args()

    local authorization, err = genawssigv4.generate_aws_sigv4(
        access_key_id, secret_access_key, region, date_iso8601, method,
        url_path, query, headers)
    if err ~= nil then
        return err
    end
    ts.server_request.header["authorization"] = authorization
    return nil
end

return {
    add_aws_sigv4_authorization = add_aws_sigv4_authorization,
}
