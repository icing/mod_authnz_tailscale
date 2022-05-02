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

#include <curl/curl.h>

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
#include "ts_whois.h"

module AP_MODULE_DECLARE_DATA authnz_tailscale_module;


typedef struct {
    const char *tailscale_socket;
} ts_srv_config_t;

static void *create_srv_config(apr_pool_t *pool, server_rec *s)
{
    ts_srv_config_t *config = apr_pcalloc(pool, sizeof(*config));

    (void)s;
    return config;
}

static void *merge_srv_config(apr_pool_t *pool, void *basev, void *addv)
{
    ts_srv_config_t *base = (ts_srv_config_t *)basev;
    ts_srv_config_t *add = (ts_srv_config_t *)addv;
    ts_srv_config_t *nsc = apr_pcalloc(pool, sizeof(*nsc));
    nsc->tailscale_socket = add->tailscale_socket? add->tailscale_socket : base->tailscale_socket;

    return nsc;
}

typedef struct {
    const char *tailscale_socket;
    ts_whois_t whois;
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
         * the last one on this connection, reset the connection information
         */
        memset(&ctx->whois, 0, sizeof(ctx->whois));
    }
    return ctx;
}

static int authenticate_ts_user(request_rec *r)
{
    ts_conn_ctx_t *ctx;
    const char *current_auth;
    apr_status_t rv;

    /* Are we active here? */
    current_auth = ap_auth_type(r);
    if (!current_auth || ap_cstr_casecmp(current_auth, "tailscale")) {
        return DECLINED;
    }

    ctx = ts_conn_ctx_rget(r);
    if (ctx->tailscale_socket) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "get whois from tailscale demon at '%s'", ctx->tailscale_socket);
        rv = ts_whois_get(&ctx->whois, r, ctx->tailscale_socket);
        if (APR_SUCCESS != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                          "no whois from tailscale demon");
            goto denied;
        }
        AP_DEBUG_ASSERT(ctx->whois.user[0]);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                      "found tailscale user: %s", ctx->whois.user);
        r->user = ctx->whois.user;
        return OK;
    }
denied:
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
    ts_conn_ctx_t *ctx;
    const char *require, *err = NULL;
    const char *tokens;
    char *w;
    apr_status_t rv;

    (void)require_args;
    ctx = ts_conn_ctx_rget(r);
    if (!ctx->tailscale_socket) {
        goto denied;
    }

    require = ap_expr_str_exec(r, parsed_require_args, &err);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                      "auth_tailscale authorize: require user: Can't evaluate expression: %s",
                      err);
        goto denied;
    }

    rv = ts_whois_get(&ctx->whois, r, ctx->tailscale_socket);
    if (APR_SUCCESS != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                      "no whois from tailscale demon");
        goto denied;
    }
    AP_DEBUG_ASSERT(ctx->whois.user[0]);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                  "found tailscale user: %s", ctx->whois.user);

    tokens = require;
    while ((w = ap_getword_conf(r->pool, &tokens)) && w[0]) {
        if (!strcmp(ctx->whois.user, w) || !strcmp("*", w)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO()
                          "auth_tailscale authorization successful");
            return AUTHZ_GRANTED;
        }
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01706)
                  "auth_tailscale authorize, user '%s' did not match: '%s'",
                  ctx->whois.user, require);

denied:
    return AUTHZ_DENIED;
}

static const authz_provider authz_tsuser_provider =
{
    &tsuser_check_authorization,
    &ts_parse_config,
};

static apr_status_t post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv = APR_SUCCESS;
    ts_srv_config_t *config;

    (void)p;
    (void)plog;
    (void)ptemp;
    (void)s;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    for (; s; s = s->next) {
        config = ap_get_module_config(s->module_config, &authnz_tailscale_module);
        if (!config->tailscale_socket) {
            config->tailscale_socket = TAILSCALE_DEF_URL;
        }
    }

    return rv;
}

static const char *cmd_ts_parse_url(cmd_parms *cmd, void *config, const char *url)
{
    ts_srv_config_t *conf = ap_get_module_config(cmd->server->module_config,
                                                 &authnz_tailscale_module);
    apr_uri_t url_parsed;

    (void)config;
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

    ap_assert(conf);
    conf->tailscale_socket = url_parsed.path;
    return NULL;
}

static const command_rec authnz_ts_cmds[] =
{
    AP_INIT_TAKE1("AuthTailscaleURL", cmd_ts_parse_url, NULL, RSRC_CONF,
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

    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(authnz_tailscale) =
{
    STANDARD20_MODULE_STUFF,
    NULL,                            /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    create_srv_config,               /* server config */
    merge_srv_config,                /* merge server config */
    authnz_ts_cmds,                  /* command apr_table_t */
    register_hooks,                  /* register hooks */
#if defined(AP_MODULE_FLAG_NONE)
    AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};
