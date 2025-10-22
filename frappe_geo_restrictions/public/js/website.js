(function () {
	if (window.__READONLY_APPLIED__) return;
	window.__READONLY_APPLIED__ = true;

	const TARGETS = "input, textarea, select, button";

	function addBanner() {
		if (document.querySelector('[data-testid="readonly-banner"]')) return;
		const b = document.createElement("div");
		b.dataset.testid = "readonly-banner";
		b.className =
			"bg-warning text-orange-400 border-orange-300 border-b px-4 py-2 text-sm font-guardian-medium text-center";
		b.textContent = "You currently have read-only access to this site.";
		document.body.insertBefore(b, document.body.firstChild || null);
	}

	function disable(el) {
		if (!(el instanceof HTMLElement)) return;

		if (el.dataset.readonlyEnforced === "1") {
			if (!el.disabled) el.disabled = true;
			return;
		}

		el.disabled = true;
		el.setAttribute("aria-readonly", "true");
		if (!el.title) el.title = "You have read-only access.";
		el.dataset.readonlyEnforced = "1";
	}

	function shouldDisable(el) {
		if (!(el instanceof HTMLElement)) return false;
		if (el.closest(".disallow-in-readonly")) return true;
		if (el.closest(".allow-in-readonly")) return false;
		return el.matches(TARGETS);
	}

	function process(root) {
		if (!(root instanceof Element || root instanceof Document)) return;

		if (root instanceof HTMLElement && root.matches(TARGETS) && shouldDisable(root))
			disable(root);

		root.querySelectorAll(TARGETS).forEach((el) => {
			if (shouldDisable(el)) disable(el);
		});

		root.querySelectorAll(".disallow-in-readonly").forEach((container) => {
			container.querySelectorAll(TARGETS).forEach(disable);
			if (container.matches(TARGETS)) disable(container);
		});
	}

	function applyAll() {
		document.documentElement.classList.add("access-tier-1");
		addBanner();
		process(document);
	}

	const nodeObserver = new MutationObserver((muts) => {
		for (const m of muts) {
			m.addedNodes.forEach((n) => {
				if (n instanceof Element) process(n);
			});
		}
	});

	const attributeObserver = new MutationObserver((mutations) => {
		for (const m of mutations) {
			if (m.type === "attributes" && m.attributeName === "disabled") {
				const el = m.target;
				if (
					el instanceof HTMLElement &&
					el.dataset.readonlyEnforced === "1" &&
					!el.disabled
				) {
					el.disabled = true;
				}
			}
		}
	});

	function blockInteraction(e) {
		const el = e.target;
		if (
			el instanceof HTMLElement &&
			el.matches(TARGETS) &&
			el.dataset.readonlyEnforced === "1"
		) {
			if (!el.disabled) el.disabled = true;
			e.stopImmediatePropagation();
			e.preventDefault();
		}
	}

	function init() {
		applyAll();

		nodeObserver.observe(document.body, { childList: true, subtree: true });
		attributeObserver.observe(document.body, {
			subtree: true,
			attributes: true,
			attributeFilter: ["disabled"],
		});

		document.addEventListener("click", blockInteraction, true);
		document.addEventListener("mousedown", blockInteraction, true);
		document.addEventListener("keydown", blockInteraction, true);
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}

	window.__applyAccessTierBoundary = applyAll;
})();
