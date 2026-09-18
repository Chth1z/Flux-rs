/* SPDX-License-Identifier: GPL-3.0-only */
#include <linux/module.h>
#include "fluxrs.h"

#ifndef FLUXRS_STAGE
#define FLUXRS_STAGE 0
#endif

static int __init fluxrs_init(void)
{
	int rc;

	rc = fluxrs_sym_init();
	if (rc)
		return rc;
	rc = fluxrs_hook_register();
	if (rc) {
		fluxrs_sym_exit();
		return rc;
	}
	rc = fluxrs_ctl_register();
	if (rc) {
		fluxrs_hook_unregister();
		fluxrs_sym_exit();
		return rc;
	}
#if !defined(FLUXRS_STAGE) || FLUXRS_STAGE < 2
	pr_info("fluxrs: loaded (bypass only; stage 0)\n");
#else
	pr_info("fluxrs: loaded (stage %d)\n", FLUXRS_STAGE);
#endif
	return 0;
}

static void __exit fluxrs_exit(void)
{
	fluxrs_ctl_unregister();
	fluxrs_hook_unregister();
	fluxrs_sym_exit();
	pr_info("fluxrs: unloaded\n");
}

module_init(fluxrs_init);
module_exit(fluxrs_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Flux-rs");
MODULE_DESCRIPTION("Flux-rs LOCAL_OUT handoff (GKI-line module)");
MODULE_ALIAS("devname:fluxrs");
