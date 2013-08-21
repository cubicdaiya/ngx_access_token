/*
 * Copyright (C) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#define NGX_HTTP_ACCESS_TOKEN_SET_ARG(r, arg, var)  \
    if (var->not_found) {                           \
        arg = NULL;                                 \
    } else {                                        \
        arg = ngx_pnalloc(r->pool, var->len + 1);   \
        if (arg == NULL) {                          \
            return;                                 \
        }                                           \
        ngx_cpystrn(arg, var->data, var->len + 1);  \
    }

typedef struct ngx_http_access_token_conf_t {
    ngx_flag_t enable;
    ngx_str_t access_key;
    ngx_str_t secret;
} ngx_http_access_token_conf_t;

typedef struct ngx_http_access_token_ctx_t {
    u_char *access_key;
    u_char *expires;
    u_char *sig;
} ngx_http_access_token_ctx_t;

static void *ngx_http_access_token_create_loc_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_access_token_init(ngx_conf_t *cf);
static char *ngx_http_access_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_access_token_handler(ngx_http_request_t *r);
static u_char *ngx_http_access_token_hmac(ngx_pool_t *pool, ngx_str_t *key, ngx_str_t *text);
static void ngx_http_access_token_set_args(ngx_http_request_t *r, ngx_http_access_token_ctx_t *ctx);
static ngx_int_t ngx_http_access_token_is_invalid_conf(ngx_http_access_token_conf_t *conf);
static ngx_str_t *ngx_http_access_token_build_plain_text(ngx_http_request_t *r, ngx_http_access_token_ctx_t *ctx);

static ngx_command_t ngx_http_access_token_commands[] = {
    { 
        ngx_string("access_token_access_key"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_conf_t, access_key),
        NULL
    },
    { 
        ngx_string("access_token_secret"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_conf_t, secret),
        NULL
    },
    { 
        ngx_string("access_token_check"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_conf_t, enable),
        NULL
    },
    ngx_null_command
};


static ngx_http_module_t ngx_http_access_token_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_access_token_init,            /* postconfiguration */
    
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_access_token_create_loc_conf, /* create location configuration */
    ngx_http_access_token_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_access_token_module = {
    NGX_MODULE_V1,
    &ngx_http_access_token_module_ctx, /* module context */
    ngx_http_access_token_commands,    /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_access_token_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_access_token_conf_t *loc_conf;
    loc_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_token_conf_t));
    if (loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }
    loc_conf->enable = NGX_CONF_UNSET;
    return loc_conf;
}

static char *ngx_http_access_token_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_access_token_conf_t *prev = parent;
    ngx_http_access_token_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_access_token_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h    = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_access_token_handler;

    return NGX_OK;
}

static ngx_int_t ngx_http_access_token_is_invalid_conf(ngx_http_access_token_conf_t *conf)
{
    if (conf->access_key.data != NULL &&
        conf->secret.data     != NULL &&
        conf->access_key.len > 0      &&
        conf->secret.len     > 0)
    {
        return NGX_OK;
    }
    return NGX_ERROR;
}

static ngx_int_t ngx_http_access_token_is_invalid_args(ngx_http_access_token_ctx_t *ctx)
{
    if (ctx->access_key != NULL &&
        ctx->expires    != NULL &&
        ctx->sig        != NULL)
    {
        return NGX_OK;
    }
    return NGX_ERROR;
}

static ngx_int_t ngx_http_access_token_handler(ngx_http_request_t *r)
{
    ngx_http_access_token_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_access_token_module);
    ngx_http_access_token_ctx_t ctx = {
        .access_key = NULL,
        .expires    = NULL,
        .sig        = NULL,
    };
    ngx_str_t *plain;
    u_char *check_sig;

    if (!conf->enable) {
        return NGX_DECLINED;
    }

    if (ngx_http_access_token_is_invalid_conf(conf) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Configuration error. You MUST specify access_token_access_key and access_token_secret");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_access_token_set_args(r, &ctx);

    if (ngx_http_access_token_is_invalid_args(&ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid request arguments");
        return NGX_HTTP_FORBIDDEN;
    }

    if (ngx_strcmp(ctx.access_key, conf->access_key.data) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "AccessKey does not match. conf:%s, request:%s", conf->access_key.data, ctx.access_key);
        return NGX_HTTP_FORBIDDEN;
    }

    if(ngx_atoi(ctx.expires, ngx_strlen(ctx.expires)) < ngx_time()) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Request has expired");
        return NGX_HTTP_FORBIDDEN;
    }

    plain     = ngx_http_access_token_build_plain_text(r, &ctx);
    check_sig = ngx_http_access_token_hmac(r->pool, &conf->secret, plain);

    if(ngx_strcmp(ctx.sig, check_sig) == 0) {
        return NGX_OK;
    } else {
        if (ctx.sig != NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid signature: %s => %s:%s", plain->data, check_sig, ctx.sig);
        }
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}

static void ngx_http_access_token_set_args(ngx_http_request_t *r, ngx_http_access_token_ctx_t *ctx)
{
    ngx_int_t                  i;
    ngx_http_variable_value_t *var;
    ngx_uint_t                 key;
    u_char                    *low[3];
    ngx_str_t                  args[3] = { 
        ngx_string("arg_accesskey"),
        ngx_string("arg_expires"),
        ngx_string("arg_signature")
    };


    for (i=0;i<3;i++) {
        low[i] = ngx_pnalloc(r->pool, args[i].len);
        if (low[i] == NULL) {
            return;
        }
        key = ngx_hash_strlow(low[i], args[i].data, args[i].len);
        var = ngx_http_get_variable(r, &args[i], key);
        switch (i) {
        case 0:
            NGX_HTTP_ACCESS_TOKEN_SET_ARG(r, ctx->access_key, var);
            break;
        case 1:
            NGX_HTTP_ACCESS_TOKEN_SET_ARG(r, ctx->expires, var);
            break;
        case 2:
            NGX_HTTP_ACCESS_TOKEN_SET_ARG(r, ctx->sig, var);
            break;
        }
    }
}

static u_char *ngx_http_access_token_hmac(ngx_pool_t *pool, ngx_str_t *key, ngx_str_t *text)
{
    u_char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    const EVP_MD *evp_md;
    u_char *result;
    ngx_str_t src, dst;

    evp_md = EVP_sha1();
    HMAC(evp_md, key->data, key->len, text->data, text->len, md, &md_len);
    if ((result = ngx_pcalloc(pool, ngx_base64_encoded_length(md_len) + 1)) == NULL) {
        return NULL;
    }

    dst.data = result;
    dst.len  = ngx_base64_encoded_length(md_len);
    src.data = md;
    src.len  = md_len;
    ngx_encode_base64(&dst, &src);

    return result;
}

static ngx_str_t *ngx_http_access_token_build_plain_text(ngx_http_request_t *r, ngx_http_access_token_ctx_t *ctx)
{
    ngx_str_t *plain;
    u_char *buf;
    size_t len;
    u_char *method_name, *uri;

    if ((plain = ngx_palloc(r->pool, sizeof(ngx_str_t))) == NULL) {
        return NULL;
    }

    len = r->method_name.len + r->uri.len + ngx_strlen(ctx->expires) + ngx_strlen(ctx->access_key);

    if ((method_name = ngx_palloc(r->pool, r->method_name.len + 1)) == NULL) {
        return NULL;
    }

    if ((uri = ngx_palloc(r->pool, r->uri.len + 1)) == NULL) {
        return NULL;
    }

    ngx_cpystrn(method_name, r->method_name.data, r->method_name.len + 1);
    ngx_cpystrn(uri,         r->uri.data,         r->uri.len + 1);

    if ((buf = ngx_palloc(r->pool, len + 1)) == NULL) {
        return NULL;
    }

    (void)ngx_snprintf(buf, len, "%s%s%s%s", method_name, uri, ctx->expires, ctx->access_key);

    plain->data = buf;
    plain->len  = len;
    plain->data[len] = '\0';

    return plain;
}
