#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_hostprotect_module.h"

static ngx_command_t ngx_http_hostprotect_commands[] = {
    { ngx_string("hostprotect"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hostprotect_loc_conf_t, enable),
      NULL },

    { ngx_string("hostprotect_debug"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hostprotect_loc_conf_t, debug),
      NULL },

    { ngx_string("hostprotect_resolver"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hostprotect_loc_conf_t, resolver),
      NULL },

    { ngx_string("hostprotect_purge_ip"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hostprotect_loc_conf_t, purge_ip),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_hostprotect_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_hostprotect_init,     /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    ngx_http_hostprotect_create_loc_conf,                         /* create location configuration */
    ngx_http_hostprotect_init_loc_conf                           /* merge location configuration */
};

ngx_module_t ngx_http_hostprotect_module = {
    NGX_MODULE_V1,
    &ngx_http_hostprotect_module_ctx,    /* module context */
    ngx_http_hostprotect_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_hostprotect_handler(ngx_http_request_t *r)
{
  ngx_http_hostprotect_loc_conf_t *alcf;
  ngx_str_t resolver;
  ngx_str_t purge_ip;
  uint32_t hash;
  ngx_slab_pool_t *shpool;
  ngx_str_node_t *found, *new_node;
  ngx_str_t ip_as_string;
  void *addr;
  char ip_as_char[16];
  int status = 0;

  memset(ip_as_char, 0, sizeof(ip_as_char));
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_hostprotect_module);
  if(!alcf->enable) {
    return NGX_OK;
  } else {
    purge_ip = alcf->purge_ip;
    resolver = alcf->resolver;
  }

  if(r->connection->sockaddr->sa_family == AF_INET) {
    addr = &(((struct sockaddr_in *) (r->connection->sockaddr))->sin_addr.s_addr);
    inet_ntop(r->connection->sockaddr->sa_family, addr, ip_as_char, sizeof ip_as_char);
  } else {
    return NGX_OK;
  }

  if(*ip_as_char == '\0')
    return NGX_OK;

  ip_as_string.data = ip_as_char;
  ip_as_string.len = strlen(ip_as_char);

  /* checking for cache */
  hash = ngx_crc32_long(ip_as_string.data, ip_as_string.len);
  shpool = (ngx_slab_pool_t *) ngx_http_hostprotect_shm_zone->shm.addr;
  ngx_shmtx_lock(&shpool->mutex);
  found = ngx_str_rbtree_lookup(ngx_http_hostprotect_rbtree, &ip_as_string, hash);
  ngx_shmtx_unlock(&shpool->mutex);

  /* purging */
  if(!strcmp((char *)purge_ip.data, ip_as_char) && r->method == HTTP_METHOD_DELETE) {

    if(alcf->debug)
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: Got request for purging from %s", MODULE_NAME, (char *)purge_ip.data);

    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i;

    int purge_status = 0;

    for(i = 0; ; i++) {
      if(i >= part->nelts) {
        if(part->next == NULL)
          break;
        part = part->next;
        data = part->elts;
        i = 0;
      }

      if(!strcmp((char *)data[i].key.data, "X-Purge-From-BL")) {
        ngx_str_t purge_data = data[i].value;
        if(alcf->debug)
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: Got header X-Purge-From-BL: %s", MODULE_NAME, (char *)purge_data.data);

        /* purge from cache */
        purge_from_cache();
        goto no_redirect;
      }
    }
  }

  /* cache hit */
  if(found != NULL && !strcmp(found->str.data, ip_as_char)) {
    /* goto redirect page */
    if(alcf->debug)
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: CACHE HIT %s", MODULE_NAME, ip_as_char);

    /* redirect */
    status = 1;
    goto err_redirect;
  } else {
  /* cache miss */

    /* check for blacklist */
    check_rbl(r, alcf, ip_as_char, resolver, &status);
    if(alcf->debug)
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: CACHE MISS %s, RBL status %d", MODULE_NAME, ip_as_char, status);

    /* if blacklisted */
    if(status) {
      if(alcf->debug)
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: %s is blacklisted!", MODULE_NAME, ip_as_char);

      /* add to cache */
      ngx_shmtx_lock(&shpool->mutex);
      new_node = ngx_slab_alloc_locked(shpool, sizeof(ngx_str_node_t));
      if(new_node != NULL) {
        if(alcf->debug)
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: ADDED to cache %s", MODULE_NAME, ip_as_char);
      } else {
        return NGX_ERROR;
      }
      new_node->node.key = hash;
      new_node->str.len = ip_as_string.len;
      new_node->str.data = ip_as_string.data;
      ngx_rbtree_insert(ngx_http_hostprotect_rbtree, &new_node->node);
      ngx_shmtx_unlock(&shpool->mutex);
    }

err_redirect:
      if(status) {
        /* return redirect page */
        ngx_buf_t *b;
        ngx_chain_t out;
        u_char err_msg[MAX_MSG];

        ngx_memzero(&err_msg, MAX_MSG);
        ngx_sprintf(err_msg, "<html><head><title>Your IP is blacklisted in bl.hostprotect.net - redirecting..</title><META http-equiv='refresh' content='3;URL=http://www.hostprotect.net/'></head><body bgcolor='#ffffff'><center>Your IP is blacklisted in bl.hostprotect.net. You will be redirected automatically in 3 seconds.</center></body></html>");

        r->headers_out.content_type.len = sizeof("text/html; charset=utf8") - 1;
        r->headers_out.content_type.data = (u_char *) "text/html; charset=utf8";
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        out.buf = b;
        out.next = NULL;
        b->pos = err_msg;
        b->last = err_msg + sizeof(err_msg);
        b->memory = 1;
        b->last_buf = 1;

        r->headers_out.status = NGX_HTTP_FORBIDDEN;
        r->headers_out.content_length_n = sizeof(err_msg);
        ngx_http_send_header(r);
        ngx_http_output_filter(r, &out);
        return NGX_HTTP_FORBIDDEN;
      } else {
no_redirect:
      return NGX_OK;
    }
  }
}

static ngx_int_t ngx_http_hostprotect_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cscf;

  cscf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  h = ngx_array_push(&cscf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
  if(h == NULL)
    return NGX_ERROR;

  *h = ngx_http_hostprotect_handler;

  ngx_str_t *shm_name;
  shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
  shm_name->len = sizeof(MODULE_NAME)-1;
  shm_name->data = (unsigned char *) MODULE_NAME;

  if(ngx_http_hostprotect_shm_size == 0)
    ngx_http_hostprotect_shm_size = SHM_SIZE;

  ngx_http_hostprotect_shm_zone = ngx_shared_memory_add(cf, shm_name, ngx_http_hostprotect_shm_size, &ngx_http_hostprotect_module);
  if(ngx_http_hostprotect_shm_zone == NULL)
    return NGX_ERROR;

  ngx_http_hostprotect_shm_zone->init = ngx_http_hostprotect_init_shm_zone;

  return NGX_OK;
}

static void *ngx_http_hostprotect_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hostprotect_loc_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hostprotect_loc_conf_t));
    if(conf == NULL)
      return NGX_CONF_ERROR;

    conf->enable = NGX_CONF_UNSET;
    conf->debug = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_hostprotect_init_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_hostprotect_loc_conf_t  *prev = parent;
  ngx_http_hostprotect_loc_conf_t  *conf = child;

  ngx_conf_merge_value(conf->enable, prev->enable, 0);
  ngx_conf_merge_value(conf->debug, prev->debug, 0);
  ngx_conf_merge_str_value(conf->purge_ip, prev->purge_ip, "31.220.23.11");
  ngx_conf_merge_str_value(conf->resolver, prev->resolver, "31.220.19.20");

  return NGX_CONF_OK;
}
