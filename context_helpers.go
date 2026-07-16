package certstore

import (
	"context"
	"fmt"
)

func contextReady(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidConfiguration)
	}
	return ctx.Err()
}
