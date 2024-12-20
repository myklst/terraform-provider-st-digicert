// Copyright (c) HashiCorp, Inc.

package alicloud

// https://error-center.alibabacloud.com/status/product/Public?spm=a2c69.11428812.pdt_dtl.4.5631tFMotFMox8
const (
	ERR_MISSING_PARAMETER_NAME                          = "Missing{ParameterName}"
	ERR_INVALID_PROTOCOL_NEED_SSL                       = "InvalidProtocol.NeedSsl"
	ERR_INVALID_PARAMETER                               = "InvalidParameter"
	ERR_INCOMPLETE_SIGNATURE                            = "IncompleteSignature"
	ERR_UNKNOWN_ERROR                                   = "UnknownError"
	ERR_INTERNAL_ERROR                                  = "InternalError"
	ERR_MISSING_PARAMETER                               = "MissingParameter"
	ERR_FORBIDDEN_ACCESS_KEY_DISABLED                   = "Forbidden.AccessKeyDisabled"
	ERR_INVALID_TIMESTAMP_FORMAT                        = "InvalidTimeStamp.Format"
	ERR_INVALID_TIMESTAMP_EXPIRED                       = "InvalidTimeStamp.Expired"
	ERR_SIGNATURE_NONCE_USED                            = "SignatureNonceUsed"
	ERR_INVALID_SIGNATURE_METHOD                        = "InvalidSignatureMethod"
	ERR_UNSUPPORTED_HTTP_METHOD                         = "UnsupportedHTTPMethod"
	ERR_SIGNATURE_DOES_NOT_MATCH                        = "SignatureDoesNotMatch"
	ERR_INVALID_SECURITY_TOKEN_MISMATCH_WITH_ACCESS_KEY = "InvalidSecurityToken.MismatchWithAccessKey"
	ERR_INVALID_SECURITY_TOKEN_MALFORMED                = "InvalidSecurityToken.Malformed"
	ERR_INVALID_SECURITY_TOKEN_EXPIRED                  = "InvalidSecurityToken.Expired"
	ERR_INVALID_PARAMETER_NAME                          = "Invalid{ParameterName}"
	ERR_INVALID_PARAMETER_FORMAT                        = "InvalidParameter.Format"
	ERR_INVALID_PARAMETER_ACCEPT                        = "InvalidParameter.Accept"
	ERR_CONTENT_LENGTH_DOES_NOT_MATCH                   = "ContentLengthDoesNotMatch"
	ERR_CONTENT_MD_5_NOT_MATCHED                        = "ContentMD5NotMatched"
	ERR_INVALID_API_NOT_FOUND                           = "InvalidApi.NotFound"
	ERR_INVALID_ACCESS_KEY_ID_NOT_FOUND                 = "InvalidAccessKeyId.NotFound"
	ERR_INVALID_ACCESS_KEY_ID_INACTIVE                  = "InvalidAccessKeyId.Inactive"
	ERR_MISSING_SECURITY_TOKEN                          = "MissingSecurityToken"
	ERR_THROTTLING_USER                                 = "Throttling.User"
	ERR_THROTTLING                                      = "Throttling"
	ERR_THROTTLING_API                                  = "Throttling.Api"
	ERR_INVALID_REGION_NOT_FOUND                        = "InvalidRegion.NotFound"
	ERR_INVALID_PRODUCT_NOT_FOUND                       = "InvalidProduct.NotFound"
)

func IsPermanentCommonError(errCode string) bool {
	switch errCode {
	case
		ERR_MISSING_PARAMETER_NAME,
		ERR_INVALID_PROTOCOL_NEED_SSL,
		ERR_INVALID_PARAMETER,
		ERR_INCOMPLETE_SIGNATURE,
		ERR_MISSING_PARAMETER,
		ERR_FORBIDDEN_ACCESS_KEY_DISABLED,
		ERR_INVALID_TIMESTAMP_FORMAT,
		ERR_INVALID_TIMESTAMP_EXPIRED,
		ERR_SIGNATURE_NONCE_USED,
		ERR_INVALID_SIGNATURE_METHOD,
		ERR_UNSUPPORTED_HTTP_METHOD,
		ERR_SIGNATURE_DOES_NOT_MATCH,
		ERR_INVALID_SECURITY_TOKEN_MISMATCH_WITH_ACCESS_KEY,
		ERR_INVALID_SECURITY_TOKEN_MALFORMED,
		ERR_INVALID_SECURITY_TOKEN_EXPIRED,
		ERR_INVALID_PARAMETER_NAME,
		ERR_INVALID_PARAMETER_FORMAT,
		ERR_INVALID_PARAMETER_ACCEPT,
		ERR_CONTENT_LENGTH_DOES_NOT_MATCH,
		ERR_CONTENT_MD_5_NOT_MATCHED,
		ERR_INVALID_API_NOT_FOUND,
		ERR_INVALID_ACCESS_KEY_ID_NOT_FOUND,
		ERR_INVALID_ACCESS_KEY_ID_INACTIVE,
		ERR_MISSING_SECURITY_TOKEN,
		ERR_INVALID_REGION_NOT_FOUND,
		ERR_INVALID_PRODUCT_NOT_FOUND:
		return true
	default:
		return false
	}
}
