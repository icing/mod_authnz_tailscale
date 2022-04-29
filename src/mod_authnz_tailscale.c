/***************************************************************************
 *                                  _   _ ____  _
 * Copyright (C) 2022, Stefan Eissing, <stefan@eissing.org>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "apr_strings.h"
#include "apr_lib.h"

#include "httpd.h"
#include "http_config.h"
#include "ap_provider.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "mod_auth.h"
#include "mod_authnz_tailscale.h"

module AP_MODULE_DECLARE_DATA authnz_tailscale_module;


typedef struct {
    apr_pool_t *pool;
    const char *tailscale_socket;
} ts_srv_config_t;

static void *create_authnz_ts_srv_config(apr_pool_t *pool, server_rec *s)
{
    ts_srv_config_t *config = apr_pcalloc(pool, sizeof(*config));

    (void)s;
    config->pool = pool;
    return config;
}

typedef struct {
    const char *tailscale_socket;
    const char *tailscale_user;
} ts_conn_ctx_t;

static ts_conn_ctx_t *ts_conn_ctx_rget(request_rec *r)
{
    conn_rec *c = r->connection;
    ts_conn_ctx_t *ctx = ap_get_module_config(c->conn_config,
                                              &authnz_tailscale_module);
    ts_srv_config_t *config = ap_get_module_config(r->server->module_config,
                                                   &authnz_tailscale_module);

    ap_assert(config->tailscale_socket);

    if (!ctx) {
        ctx = apr_pcalloc(r->connection->pool, sizeof(*ctx));
        ctx->tailscale_socket = config->tailscale_socket;
        ap_set_module_config(c->conn_config, &authnz_tailscale_module, ctx);
    }
    else if (strcmp(config->tailscale_socket, ctx->tailscale_socket)) {
        /* if this request has another tailscale socket configured than
         * the last one on this connection
         * (for whatever reason, it does not make sense, I think),
         * reset the connection information */
        ctx->tailscale_user = NULL;
    }
    return ctx;
}

static int authenticate_ts_user(request_rec *r)
{
    ts_conn_ctx_t *ctx;
    const char *current_auth;

    /* Are we active here? */
    current_auth = ap_auth_type(r);
    if (!current_auth || ap_cstr_casecmp(current_auth, "Tailscale")) {
        return DECLINED;
    }

    ctx = ts_conn_ctx_rget(r);
    if (ctx->tailscale_socket) {
        /* TODO: lookup user at tailscale socket */
    }
    return HTTP_UNAUTHORIZED;
}

static const char *ts_parse_config(cmd_parms *cmd, const char *require_line,
                                   const void **parsed_require_line)
{
    const char *expr_err = NULL;
    ap_expr_info_t *expr;

    expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);
    if (expr_err)
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);

    *parsed_require_line = expr;
    return NULL;
}

static authz_status tsuser_check_authorization(request_rec *r,
                                               const char *require_args,
                                               const void *parsed_require_args)
{
    (void)r;
    (void)require_args;
    (void)parsed_require_args;
    return AUTHZ_DENIED;
}

static const authz_provider authz_tsuser_provider =
{
    &tsuser_check_authorization,
    &ts_parse_config,
};

static const char *cmd_ts_parse_url(cmd_parms *cmd, void *config, const char *url)
{
    ts_srv_config_t *dirconf = config;
    apr_uri_t url_parsed;

    memset(&url_parsed, 0, sizeof(url_parsed));
    if (APR_SUCCESS != apr_uri_parse(cmd->pool, url, &url_parsed)) {
        return "not an url";
    }
    if (url_parsed.scheme && url_parsed.scheme[0]
        && strcmp("file", url_parsed.scheme)) {
        return "not a supported scheme";
    }
    if (url_parsed.hostname  && url_parsed.hostname[0]
        && strcmp("localhost", url_parsed.hostname)) {
        return "hosts other than 'localhost' not supported";
    }
    if (!url_parsed.path || !url_parsed.path[0]) {
        return "path to tailscale unix socket missing";
    }

    dirconf->tailscale_socket = url_parsed.path;
    return NULL;
}

static const command_rec authnz_ts_cmds[] =
{
    AP_INIT_TAKE1("AuthTailscaleURL", cmd_ts_parse_url, NULL, OR_AUTHCFG,
                  "URL or path to unix socket of tailscale demon"),
    AP_INIT_TAKE1(NULL, NULL, NULL, RSRC_CONF, NULL)
};

static void register_hooks(apr_pool_t *p)
{
    /* Register authn method */
    ap_hook_check_authn(authenticate_ts_user, NULL, NULL, APR_HOOK_MIDDLE,
                        AP_AUTH_INTERNAL_PER_CONF);

    /* Register authz providers */
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "tailscale-user",
                              AUTHZ_PROVIDER_VERSION,
                              &authz_tsuser_provider,
                              AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authnz_tailscale) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                            /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    create_authnz_ts_srv_config,     /* server config */
    NULL,                            /* merge server config */
    authnz_ts_cmds,                  /* command apr_table_t */
    register_hooks,                   /* register hooks */
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};
