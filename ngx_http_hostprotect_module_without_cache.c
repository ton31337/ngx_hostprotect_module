#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#define MODULE_NAME "hostprotect"
#define MAX_MSG 1024

struct dns_header
{
  unsigned short id; // 16 bits
  unsigned char rd :1; // 1 bit
  unsigned char tc :1; // 1 bit
  unsigned char aa :1; // 1 bit
  unsigned char opcode :4; // 4 bits
  unsigned char qr :1; // 1 bit
  unsigned char rcode :4; // 4 bits
  unsigned char cd :1; // 1 bit
  unsigned char ad :1; // 1 bit
  unsigned char z :1; // 1 bit
  unsigned char ra :1; // 1 bit
  unsigned short qcount; // 16 bits
  unsigned short ancount; // 16 bits
  unsigned short nscount; // 16 bits
  unsigned short arcount; // 16 bits
};

struct dns_question
{
  unsigned short qtype; // 16 bits
  unsigned short qclass; // 16 bits
};

struct dns_answer
{
  unsigned char *name; // 32 bits
  struct dns_question *q_params; // 32 bits
  unsigned int ttl; // 32 bits
  unsigned short rdlength; // 16 bits
  unsigned char *data; // 32 bits
};

typedef struct {
  ngx_flag_t enable;
  ngx_str_t resolver;
  ngx_flag_t debug;
} ngx_http_hostprotect_loc_conf_t;

static ngx_int_t ngx_http_hostprotect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hostprotect_init(ngx_conf_t *cf);
static void *ngx_http_hostprotect_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hostprotect_init_loc_conf(ngx_conf_t *cf, void *parent, void *child);
void inline __attribute__((always_inline)) swap_bytes(unsigned char *, unsigned char *);
char inline __attribute__((always_inline)) *change_to_dns_format(unsigned char *);
static void check_rbl(ngx_http_request_t *, ngx_http_hostprotect_loc_conf_t *, char *, ngx_str_t, int *);

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

void inline __attribute__((always_inline)) swap_bytes(unsigned char *orig, unsigned char *changed)
{
  int i = 3;
  int j;
  char *tmp[4];
  char *t = strtok(strdup(orig), ".");
  while(t != NULL) {
    tmp[i--] = t;
    t = strtok(NULL, ".");
  }
  for(j = 0; j < 4; j++) {
    strcat(changed, tmp[j]);
    strcat(changed, ".");
  }
  strcat(changed, "in-addr.arpa");
}

char inline __attribute__((always_inline)) *change_to_dns_format(unsigned char *orig)
{
  int init[] = {47,-84,1,0,0,1,0,0,0,0,0,0};
  int end[] = {0,0,12,0,1,0};
  char *t = strtok(strdup(orig), ".");
  char ip[48];
  int i, n;
  int j = sizeof(init) / sizeof(init[0]);
  int m = sizeof(end) / sizeof(end[0]);
  int k = sizeof(ip) / sizeof(ip[0]);

  for(i = 0; i < j; i++) {
    ip[i] = init[i];
  }

  while(t != NULL) {
    int l = strlen(t);
    int x = 0;
    ip[i++] = l; //12
    ip[i++] = *t; //13
    if(l > 1) {
      --i;
      for(x; x < l; x++) {
        ip[++i] = *(++t);
      }
    }
    t = strtok(NULL, ".");
  }

  for(n = 0; n < m; n++) {
    ip[i++] = end[n];
  }

  return ip;
}

static void check_rbl(ngx_http_request_t *req, ngx_http_hostprotect_loc_conf_t *conf, char *ip, ngx_str_t resolver, int *status)
{
  int s;
  int r;
  int j = 0;
  int p = 13;
  struct sockaddr_in addr;
  struct timeval tv;
  char buf[65536];
  char host[40];
  unsigned char *qname;
  struct dns_answer *ans;
  struct dns_header *dns;
  unsigned char *reader = NULL;
  char *packet;
  fd_set readfds;

  tv.tv_sec = 0;
  tv.tv_usec = 5000;
  FD_ZERO(&readfds);

  s = socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_IP);
  FD_SET(s, &readfds);

  memset(buf, 0, sizeof(buf));
  memset(&addr, 0, sizeof(addr));
  memset(host, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(53);
  addr.sin_addr.s_addr = inet_addr(resolver.data);

  swap_bytes(ip, host);
  packet = change_to_dns_format(host);
  connect(s, (struct sockaddr *)&addr, sizeof(addr));
  send(s, (void *)packet, 48, MSG_NOSIGNAL);

  r = select(s+1, &readfds, NULL, NULL, &tv);
  if(r) {
    if(FD_ISSET(s, &readfds)) {
      int bytes_recv = recv(s, buf, sizeof(buf), 0);
      /* don't forget to close the socket, because you will reach socket limit by pid */
      close(s);
      if(bytes_recv) {
        /* if debug */
        if(conf->debug)
          ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "%s: %d bytes received from server for %s", MODULE_NAME, bytes_recv, ip);

        if(bytes_recv != 78)
          goto err_go;

        qname = (unsigned char*)&buf[sizeof(struct dns_header)];
        reader = &buf[sizeof(struct dns_header) + (strlen(qname)+1) + sizeof(struct dns_question)];
      }
    }
  }

  ans = (struct dns_answer *)reader;
  if(ans != NULL) {
    ans->data = (unsigned char *) malloc(ntohs(ans->rdlength));
    for(j; j < ntohs(ans->rdlength); j++)
      ans->data[j] = reader[j];

    if(ans->data[p++] == '1' && ans->data[++p] == 'b')
      *status = 1;
  }

  err_go:
    return;

}

static ngx_int_t ngx_http_hostprotect_handler(ngx_http_request_t *r)
{
  ngx_http_hostprotect_loc_conf_t *alcf;
  ngx_str_t resolver;
  void *addr;
  char ip_as_char[15];
  int status = 0;

  memset(ip_as_char, 0, sizeof(ip_as_char));
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_hostprotect_module);
  if(!alcf->enable) {
    return NGX_OK;
  } else {
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

   check_rbl(r, alcf, ip_as_char, resolver, &status);
   /* if debug */
   if(alcf->debug)
     ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: checking for %s using resolver %s, request-length: %d, status %d", MODULE_NAME, ip_as_char, resolver.data, r->request_length, status);

  if(status) {
    /* if debug */
    if(alcf->debug)
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s: %s is blacklisted!", MODULE_NAME, ip_as_char);

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
  ngx_conf_merge_str_value(conf->resolver, prev->resolver, "31.220.19.20");

  return NGX_CONF_OK;
}
