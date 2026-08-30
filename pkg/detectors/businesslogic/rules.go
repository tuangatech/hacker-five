package businesslogic

const (
	// DefaultAuthHeaderName/DefaultAuthHeaderFormat match every other
	// detector's own default — see authbypass/ssrf's identical constants.
	DefaultAuthHeaderName   = "Authorization"
	DefaultAuthHeaderFormat = "Bearer {token}"

	// DefaultCouponMintPath/DefaultCouponApplyPath are crAPI's real routes —
	// confirmed via source (services/community/api/controllers/
	// coupon_controller.go's AddNewCoupon, services/workshop/crapi/shop/
	// views.py's ApplyCouponView) and a live exploit chain (2026-08-29), not
	// guessed. "Hardcode patterns for known apps" per
	// docs/13-implementation-plan-ph4.md Step 3's own scoping — overridable
	// via WithCouponPaths for a different target.
	DefaultCouponMintPath  = "/community/api/v2/coupon/new-coupon"
	DefaultCouponApplyPath = "/workshop/api/shop/apply_coupon"

	// DefaultRaceConcurrency is how many simultaneous apply requests
	// checkCouponApplyRace fires via the last-byte-sync race client — enough
	// to reliably land inside a real check-then-act window without being
	// excessive load against the target.
	DefaultRaceConcurrency = 15

	// injectedCreditAmount is the inflated amount checkCouponSelfMintCredit
	// mints and applies — large enough to be unambiguous evidence of a real
	// unearned-credit bug, not a value a legitimate coupon would plausibly
	// carry.
	injectedCreditAmount = "999999"
)
