// Copyright (c) HashiCorp, Inc.

package aws

const (
	ERR_CODE_ACCESS_DENIED_EXCEPTION       = "AccessDeniedException"
	ERR_CODE_INCOMPLETE_SIGNATURE          = "IncompleteSignature"
	ERR_CODE_INTERNAL_FAILURE              = "InternalFailure"
	ERR_CODE_INVALID_ACTION                = "InvalidAction"
	ERR_CODE_INVALID_CLIENT_TOKEN_ID       = "InvalidClientTokenId"
	ERR_CODE_INVALID_PARAMETER_COMBINATION = "InvalidParameterCombination"
	ERR_CODE_INVALID_PARAMETER_VALUE       = "InvalidParameterValue"
	ERR_CODE_INVALID_QUERY_PARAMETER       = "InvalidQueryParameter"
	ERR_CODE_MALFORMED_QUERY_STRING        = "MalformedQueryString"
	ERR_CODE_MISSING_ACTION                = "MissingAction"
	ERR_CODE_MISSING_AUTHENTICATION_TOKEN  = "MissingAuthenticationToken"
	ERR_CODE_MISSING_PARAMETER             = "MissingParameter"
	ERR_CODE_NOT_AUTHORIZED                = "NotAuthorized"
	ERR_CODE_OPT_IN_REQUIRED               = "OptInRequired"
	ERR_CODE_REQUEST_EXPIRED               = "RequestExpired"
	ERR_CODE_SERVICE_UNAVAILABLE           = "ServiceUnavailable"
	ERR_CODE_THROTTLING_EXCEPTION          = "ThrottlingException"
	ERR_CODE_VALIDATION_ERROR              = "ValidationError"
	ERR_CODE_INVALID_CHANGE_BATCH          = "InvalidChangeBatch"
)

func IsPermanentCommonError(errCode string) bool {
	switch errCode {
	case
		ERR_CODE_ACCESS_DENIED_EXCEPTION,
		ERR_CODE_INCOMPLETE_SIGNATURE,
		ERR_CODE_INVALID_ACTION,
		ERR_CODE_INVALID_CLIENT_TOKEN_ID,
		ERR_CODE_INVALID_PARAMETER_COMBINATION,
		ERR_CODE_INVALID_PARAMETER_VALUE,
		ERR_CODE_INVALID_QUERY_PARAMETER,
		ERR_CODE_MALFORMED_QUERY_STRING,
		ERR_CODE_MISSING_ACTION,
		ERR_CODE_MISSING_AUTHENTICATION_TOKEN,
		ERR_CODE_MISSING_PARAMETER,
		ERR_CODE_NOT_AUTHORIZED,
		ERR_CODE_OPT_IN_REQUIRED,
		ERR_CODE_INVALID_CHANGE_BATCH,
		ERR_CODE_VALIDATION_ERROR:
		return true
	default:
		return false
	}
}
