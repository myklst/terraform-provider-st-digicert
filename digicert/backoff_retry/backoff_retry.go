package backoff_retry

import (
	"time"

	"github.com/cenkalti/backoff/v4"
)

func RetryOperator(function func() error, DefaultMaxElapsedTime time.Duration) error {
	reconnectBackoff := backoff.NewExponentialBackOff()
	reconnectBackoff.MaxElapsedTime = DefaultMaxElapsedTime
	return backoff.Retry(function, reconnectBackoff)
}
