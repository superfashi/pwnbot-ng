package thrower

import (
	"context"

	"go.uber.org/zap"
)

// scoreExploit is a scoring function that evaluates the effectiveness of an exploit
// against a given service for a specific team. It returns a score as a float64 that is
// in range [-1, 1].
// The scorer can consider various factors such as previous performance, exploit running time,
// and manual priority adjustments.
// Always returning 0 makes the scheduler round-robin through all exploits.
func scoreExploit(ctx context.Context, logger *zap.Logger, team, service, exploit string) float64 {
	return 0
}
