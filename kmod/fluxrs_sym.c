/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * Resolve nf_tproxy_* at runtime via __symbol_get (GKI ABI). Never emit
 * those names as link undefs.
 */
#include <linux/module.h>
#include "fluxrs.h"

fluxrs_get_sock_v4_t fluxrs_get_sock_v4;
fluxrs_get_sock_v6_t fluxrs_get_sock_v6;
fluxrs_tw4_t fluxrs_tw4;
fluxrs_tw6_t fluxrs_tw6;
fluxrs_laddr4_t fluxrs_laddr4;
fluxrs_laddr6_t fluxrs_laddr6;

static void *grab(const char *name)
{
	void *sym = __symbol_get(name);

	if (!sym)
		pr_warn("fluxrs: missing symbol %s\n", name);
	return sym;
}

int fluxrs_sym_init(void)
{
	fluxrs_get_sock_v4 = grab("nf_tproxy_get_sock_v4");
	fluxrs_get_sock_v6 = grab("nf_tproxy_get_sock_v6");
	fluxrs_tw4 = grab("nf_tproxy_handle_time_wait4");
	fluxrs_tw6 = grab("nf_tproxy_handle_time_wait6");
	fluxrs_laddr4 = grab("nf_tproxy_laddr4");
	fluxrs_laddr6 = grab("nf_tproxy_laddr6");

	if (!fluxrs_sym_ready()) {
		pr_warn("fluxrs: nf_tproxy incomplete; steal disabled\n");
		fluxrs_sym_exit();
		return 0;
	}
	pr_info("fluxrs: nf_tproxy symbols resolved\n");
	return 0;
}

void fluxrs_sym_exit(void)
{
	if (fluxrs_get_sock_v4) {
		__symbol_put("nf_tproxy_get_sock_v4");
		fluxrs_get_sock_v4 = NULL;
	}
	if (fluxrs_get_sock_v6) {
		__symbol_put("nf_tproxy_get_sock_v6");
		fluxrs_get_sock_v6 = NULL;
	}
	if (fluxrs_tw4) {
		__symbol_put("nf_tproxy_handle_time_wait4");
		fluxrs_tw4 = NULL;
	}
	if (fluxrs_tw6) {
		__symbol_put("nf_tproxy_handle_time_wait6");
		fluxrs_tw6 = NULL;
	}
	if (fluxrs_laddr4) {
		__symbol_put("nf_tproxy_laddr4");
		fluxrs_laddr4 = NULL;
	}
	if (fluxrs_laddr6) {
		__symbol_put("nf_tproxy_laddr6");
		fluxrs_laddr6 = NULL;
	}
}

bool fluxrs_sym_ready(void)
{
	return fluxrs_get_sock_v4 && fluxrs_get_sock_v6 && fluxrs_tw4 &&
	       fluxrs_tw6 && fluxrs_laddr4 && fluxrs_laddr6;
}
