package eval

// Arm is one configuration of `hackerfive agent` the ablation harness compares
// (docs/94-llm-finding-capability-strategy.md, Phase 0). The point of arms is
// that the *only* difference between two rows of the result table is the
// listed flags, so a difference in findings, cost or time is attributable.
//
// Later phases register their arm here when their flag lands — the app-model
// and hypothesis steps (J1/J2), the skeptic (J4), the coverage-ledger stop
// (J5) — so each is measured against the same control and the same labs before
// it is trusted. Nothing is compared until it has an arm.
type Arm struct {
	Name        string
	Description string
	// NeedsModel arms are skipped when no LLM tier is configured.
	NeedsModel bool
	ExtraArgs  []string
}

// Arms are the configurations that exist today, control first.
var Arms = []Arm{
	{
		Name:        "no-model",
		Description: "control: the deterministic fast lane only, zero LLM calls (--no-model); leaves needing a decision are left undispatched",
		ExtraArgs:   []string{"--no-model"},
	},
	{
		Name:        "model-every-turn",
		Description: "the agent as it was before LT-172: the model is asked before every leaf (--fast-lane=false)",
		NeedsModel:  true,
		ExtraArgs:   []string{"--fast-lane=false"},
	},
	{
		Name:        "fast-lane+model",
		Description: "the agent as shipped: parameter-free leaves run directly, the model decides the rest",
		NeedsModel:  true,
	},
}

// ArmByName returns the arm called name.
func ArmByName(name string) (Arm, bool) {
	for _, a := range Arms {
		if a.Name == name {
			return a, true
		}
	}
	return Arm{}, false
}
