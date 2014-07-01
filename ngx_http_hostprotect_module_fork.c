#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#define MODULE_NAME "hostprotect"
#define SHM_SIZE 16777216
#define MAX_MSG 1024
#define MAX_BUF 128
#define HTTP_METHOD_DELETE 32

typedef struct {
  ngx_flag_t enable;
  ngx_str_t purge_ip;
  ngx_str_t resolver;
  ngx_uint_t expire;
} ngx_http_hostprotect_loc_conf_t;

typedef struct {
  ngx_str_node_t sn;
  time_t expire;
  int result;
} ngx_http_hostprotect_value_node_t;

typedef struct {
  ngx_rbtree_t *tree;
  time_t expire;
} ngx_http_hostprotect_shm_data_t;

static ngx_uint_t ngx_http_hostprotect_shm_size;
static ngx_shm_zone_t *ngx_http_hostprotect_shm_zone;
static ngx_rbtree_t * ngx_http_hostprotect_rbtree;
static ngx_http_hostprotect_value_node_t *ngx_http_hostprotect_delete_expired(ngx_slab_pool_t *shpool, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_hostprotect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hostprotect_init(ngx_conf_t *cf);
static void *ngx_http_hostprotect_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hostprotect_init_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_hostprotect_commands[] = {
    { ngx_string("hostprotect"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hostprotect_loc_conf_t, enable),
      NULL },

    { ngx_string("hostprotect_purge_ip"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hostprotect_loc_conf_t, purge_ip),
      NULL },

    { ngx_string("hostprotect_resolver"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hostprotect_loc_conf_t, resolver),
      NULL },

    { ngx_string("hostprotect_expire"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_hostprotect_loc_conf_t, expire),
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

inline static void __attribute__((always_inline)) check_rbl(char *ip, ngx_str_t dns, int *status)
{
  int fd[2];
  char *buf = NULL;
  char *ns = NULL;
  int len = 0;
  pid_t child;

  pipe(fd);
  child = fork();
  if(!child) {
    close(fd[0]);
    dup2(fd[1], 1);
    len = dns.len + 2;
    ns = (char *)calloc(len, len);
    snprintf(ns, len, "@%s", dns.data);
    execlp("dig", "dig", "-x", ip, "+short", "+time=1", ns, NULL);
  } else {
    close(fd[1]);
    buf = (char *)calloc(MAX_BUF, MAX_BUF);
    read(fd[0], buf, MAX_BUF);
    if(*buf == '1' && *(++buf) == 0x2e)
      *status = 1;
  }
}

static int purge_from_cache(ngx_rbtree_t *rbtree, ngx_str_t ip)
{
  uint32_t hash;
  ngx_http_hostprotect_value_node_t *found;

  hash = ngx_crc32_long(ip.data, ip.len);
  found = (ngx_http_hostprotect_value_node_t *) ngx_str_rbtree_lookup(rbtree, &ip, hash);
  if(found) {
    ngx_rbtree_delete(rbtree, &found->sn.node);
    return 1;
  }

  return 0;
}

static ngx_int_t ngx_http_hostprotect_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
  ngx_slab_pool_t *shpool;
  ngx_rbtree_t *tree;
  ngx_rbtree_node_t *sentinel;

  shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

  if(data) {
    shm_zone->data = data;
    return NGX_OK;
  }

  tree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
  if(tree == NULL) {
    ngx_slab_free(shpool, tree);
    return NGX_ERROR;
  }

  sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
  if(sentinel == NULL) {
    ngx_slab_free(shpool, sentinel);
    return NGX_ERROR;
  }

  ngx_rbtree_sentinel_init(sentinel);
  ngx_rbtree_init(tree, sentinel, ngx_str_rbtree_insert_value);
  shm_zone->data = tree;
  ngx_http_hostprotect_rbtree = tree;

  return NGX_OK;
}

static ngx_http_hostprotect_value_node_t *ngx_http_hostprotect_delete_expired(ngx_slab_pool_t *shpool, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
  ngx_http_hostprotect_value_node_t *cur_node;
  ngx_http_hostprotect_value_node_t *found_node = NULL;
  ngx_http_hostprotect_value_node_t *tmp_node;

  if(node == sentinel) {
    return NULL;
  }

  if(node->left != sentinel) {
    tmp_node = ngx_http_hostprotect_delete_expired(shpool, node->left, sentinel);
    if(tmp_node) {
      found_node = tmp_node;
    }
  }

  if(node->right != sentinel) {
    tmp_node = ngx_http_hostprotect_delete_expired(shpool, node->right, sentinel);
    if(tmp_node) {
      found_node = tmp_node;
    }
  }

  cur_node = (ngx_http_hostprotect_value_node_t *) node;
  if(ngx_time() > cur_node->expire) {
    ngx_rbtree_delete(ngx_http_hostprotect_rbtree, node);
    ngx_slab_free_locked(shpool, node);
  }

  return found_node;
}

static ngx_int_t ngx_http_hostprotect_handler(ngx_http_request_t *r)
{
  ngx_http_hostprotect_loc_conf_t *alcf;
  ngx_slab_pool_t *shpool;
  ngx_http_hostprotect_value_node_t *found, *new_node;
  uint32_t hash;
  ngx_str_t purge_ip;
  ngx_str_t resolver;
  ngx_uint_t exp;
  ngx_str_t ip_as_string;
  void *addr;
  char ip_as_char[15];
  int status = 0;

  memset(ip_as_char, 0, sizeof(ip_as_char));
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_hostprotect_module);
  if(!alcf->enable) {
    return NGX_OK;
  } else {
    exp = alcf->expire;
    purge_ip = alcf->purge_ip;
    resolver = alcf->resolver;
  }

  if(r->connection->sockaddr->sa_family == AF_INET) {
    addr = &(((struct sockaddr_in *) (r->connection->sockaddr))->sin_addr.s_addr);
    inet_ntop(r->connection->sockaddr->sa_family, addr, ip_as_char, sizeof ip_as_char);
  } else {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "IPv6 is not supported!");
    return NGX_OK;
  }

  ip_as_string.data = ip_as_char;
  ip_as_string.len = strlen(ip_as_char);

  hash = ngx_crc32_long(ip_as_string.data, ip_as_string.len);
  shpool = (ngx_slab_pool_t *) ngx_http_hostprotect_shm_zone->shm.addr;
  ngx_shmtx_lock(&shpool->mutex);
  found = (ngx_http_hostprotect_value_node_t *) ngx_str_rbtree_lookup(ngx_http_hostprotect_rbtree, &ip_as_string, hash);
  ngx_shmtx_unlock(&shpool->mutex);

    if(found) {
      if(ngx_time() > found->expire) {
        ngx_shmtx_lock(&shpool->mutex);
        ngx_rbtree_delete(ngx_http_hostprotect_rbtree, &found->sn.node);
        ngx_slab_free_locked(shpool, found);
        ngx_shmtx_unlock(&shpool->mutex);
      }

      if(found->result > 0) {
        status = 1;
        /* Avoid double checking for DNS */
        goto err_go;
      }

      return NGX_OK;
    }

  check_rbl(ip_as_char, resolver, &status);
  ngx_shmtx_lock(&shpool->mutex);
  ngx_http_hostprotect_delete_expired(shpool, ngx_http_hostprotect_rbtree->root, ngx_http_hostprotect_rbtree->sentinel);
  new_node = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_hostprotect_value_node_t));
  if(new_node == NULL)
    return NGX_ERROR;

  new_node->sn.node.key = hash;
  new_node->sn.str.len = ip_as_string.len;
  new_node->sn.str.data = ip_as_string.data;
  new_node->result = status;
  new_node->expire = ngx_time() + exp;
  ngx_rbtree_insert(ngx_http_hostprotect_rbtree, &new_node->sn.node);
  ngx_shmtx_unlock(&shpool->mutex);

  err_go:
  if(status) {
    /* Instant purge */
    if(!strcmp((char *)purge_ip.data, ip_as_char) && r->method == HTTP_METHOD_DELETE) {
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
          purge_status = purge_from_cache(ngx_http_hostprotect_rbtree, purge_data);
          if(purge_status)
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Purging %s", (char *)purge_data.data);
        }
      }
    }
    /* Instant purge END */

    ngx_buf_t *b;
    ngx_chain_t out;
    u_char err_msg[MAX_MSG];

    ngx_memzero(&err_msg, MAX_MSG);
    ngx_sprintf(err_msg, "<html><head><title>Your IP is blacklisted in bl.hostprotect.net - redirecting..</title><META http-equiv='refresh' content='3;URL=http://www.hostprotect.net/'></head><body bgcolor='#ffffff'><center>Your IP is blacklisted in bl.hostprotect.net. You will be redirected automatically in 3 seconds.</center></body></html>");
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%p %p %p %s is blacklisted!", r, r->main, r->parent, ip_as_char);

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
    return ngx_http_output_filter(r, &out);
  }

  return NGX_OK;

}

static ngx_int_t ngx_http_hostprotect_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cscf;

  cscf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  h = ngx_array_push(&cscf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
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
    conf->expire = NGX_CONF_UNSET_UINT;
    return conf;
}

static char *ngx_http_hostprotect_init_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_hostprotect_loc_conf_t  *prev = parent;
  ngx_http_hostprotect_loc_conf_t  *conf = child;

  ngx_conf_merge_value(conf->enable, prev->enable, 0);
  ngx_conf_merge_uint_value(conf->expire, prev->expire, 10);
  ngx_conf_merge_str_value(conf->purge_ip, prev->purge_ip, "31.170.160.11");
  ngx_conf_merge_str_value(conf->resolver, prev->resolver, "31.220.19.20");

  return NGX_CONF_OK;
}
