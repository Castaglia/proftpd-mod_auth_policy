/*
 * ProFTPD: mod_auth_policy -- a module for setting authentication policies
 * Copyright (c) 2021 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_auth_policy, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"

#define MOD_AUTH_POLICY_VERSION		"mod_auth_policy/0.0"

module auth_policy_module;

static int auth_policy_engine = FALSE;

/* Implemented policies */
#define AUTH_POLICY_REQUIRE_VALID_USER		0x001

static const char *trace_channel = "auth_policy";

/* Command handlers
 */

MODRET auth_policy_pre_user(cmd_rec *cmd) {
  config_rec *c;
  unsigned long policies;

  if (auth_policy_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  c = find_config(main_server->conf, CONF_PARAM, "AuthPolicy", FALSE);
  if (c == NULL) {
    pr_trace_msg(trace_channel, 9,
      "no AuthPolicy configured, ignoring USER command");
    return PR_DECLINED(cmd);
  }

  policies = *((unsigned long *) c->argv[0]);

  if (policies & AUTH_POLICY_REQUIRE_VALID_USER) {
    const char *denymsg = NULL, *username;

    username = cmd->arg;

    if (pr_auth_getpwnam(cmd->tmp_pool, username) != NULL) {
      pr_trace_msg(trace_channel, 9,
        "AuthPolicy RequireValidUser satisfied: user '%s' is known/valid",
        username);
      return PR_DECLINED(cmd);
    }

    pr_trace_msg(trace_channel, 3,
      "AuthPolicy RequireValidUser violated: user '%s' is unknown/invalid",
      username);

    /* Check for AccessDenyMsg */
    denymsg = get_param_ptr(cmd->server->conf, "AccessDenyMsg", FALSE);
    if (denymsg != NULL) {
      if (strstr(denymsg, "%u") != NULL) {
        denymsg = sreplace(cmd->tmp_pool, denymsg, "%u", username, NULL);
      }
    } else {
      denymsg = _("Access denied.");
    }

    /* Note: while I prefer to return 421, apparently some broken, assumption-
     * making FTP clients (may they all be replaced) choke on that, and
     * require 530 instead.  Sigh.
     */
    pr_log_pri(PR_LOG_INFO, MOD_AUTH_POLICY_VERSION
      ": USER '%s' rejected by AuthPolicy RequireValidUser", username);
    pr_response_send_async(R_530, "%s", denymsg);

    /* Should we be polite, and simply return the error response, or should
     * we disconnect the client as well, to prevent it from ignoring our
     * response and trying to send the password anyway?
     */

    pr_event_generate("mod_auth_policy.require-valid-user", username);
    pr_session_disconnect(&auth_policy_module, PR_SESS_DISCONNECT_MODULE_ACL,
      "AuthPolicy RequireValidUser");
  }

  return PR_DECLINED(cmd);
}

/* Configuration handlers
 */

/* usage: AuthPolicy policy ... */
MODRET set_authpolicy(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  unsigned long policies = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "RequireValidUser") == 0) {
      policies |= AUTH_POLICY_REQUIRE_VALID_USER;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown AuthPolicy '",
        cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = policies;

  return PR_HANDLED(cmd);
}

/* usage: AuthPolicyEngine on|off */
MODRET set_authpolicyengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* Initialization functions
 */

static int auth_policy_sess_init(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "AuthPolicyEngine", FALSE);
  if (c != NULL) {
    auth_policy_engine = *((int *) c->argv[0]);
  }

  return 0;
}

/* Module API tables
 */

static conftable auth_policy_conftab[] = {
  { "AuthPolicy",		set_authpolicy,		NULL },
  { "AuthPolicyEngine",		set_authpolicyengine,	NULL },
  { NULL }
};

static cmdtable auth_policy_cmdtab[] = {
  { PRE_CMD,	C_USER,	G_NONE,	auth_policy_pre_user, FALSE, FALSE, CL_AUTH },
  { 0, NULL }
};

module auth_policy_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "auth_policy",

  /* Module configuration handler table */
  auth_policy_conftab,

  /* Module command handler table */
  auth_policy_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  auth_policy_sess_init,

  /* Module version */
  MOD_AUTH_POLICY_VERSION
};
