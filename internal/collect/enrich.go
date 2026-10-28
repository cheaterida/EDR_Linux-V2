package collect

import "edr/internal/event"

// EnrichStage reads /proc for process events before detection. It only
// touches the fields the caller asked for, so the cost tracks the active
// rule set.
type EnrichStage struct {
	Fields Fields
	// Kinds restricts which event families get enriched. A nil map means
	// KindExec only (the common case for cmdline/env rules).
	Kinds map[event.Kind]bool
	// Provider, when set, overrides Fields at each event, so a policy reload
	// can change the enrichment set without rebuilding the pipeline.
	Provider func() Fields
}

// Name implements pipeline.Stage.
func (EnrichStage) Name() string { return "enrich" }

// Handle implements pipeline.Stage. Enrichment never drops an event.
func (s EnrichStage) Handle(ev *event.Event) (bool, error) {
	if ev == nil || !s.applies(ev.Kind) {
		return true, nil
	}
	fields := s.Fields
	if s.Provider != nil {
		fields = s.Provider()
	}
	Enrich(ev, fields)
	return true, nil
}

func (s EnrichStage) applies(k event.Kind) bool {
	if s.Kinds == nil {
		return k == event.KindExec
	}
	return s.Kinds[k]
}
