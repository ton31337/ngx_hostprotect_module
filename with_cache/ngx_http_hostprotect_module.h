#define MODULE_NAME "hostprotect"
#define MAX_MSG 1024
#define HTTP_METHOD_DELETE 32
#define SHM_SIZE 16777216

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
  ngx_str_t purge_ip;
} ngx_http_hostprotect_loc_conf_t;

static ngx_uint_t ngx_http_hostprotect_shm_size;
static ngx_shm_zone_t *ngx_http_hostprotect_shm_zone;
static ngx_rbtree_t *ngx_http_hostprotect_rbtree;
static ngx_int_t ngx_http_hostprotect_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hostprotect_init(ngx_conf_t *cf);
static void *ngx_http_hostprotect_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hostprotect_init_loc_conf(ngx_conf_t *cf, void *parent, void *child);
void inline __attribute__((always_inline)) swap_bytes(unsigned char *, unsigned char *);
char inline __attribute__((always_inline)) *change_to_dns_format(unsigned char *);
static void check_rbl(ngx_http_request_t *, ngx_http_hostprotect_loc_conf_t *, char *, ngx_str_t, int *);
void purge_from_cache(void);

void purge_from_cache(void)
{
  ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) ngx_http_hostprotect_shm_zone->shm.addr;
  ngx_rbtree_node_t *root = ngx_http_hostprotect_rbtree->root;

  int i = 0, j = 0;
  while(root->left != NULL) {
    ngx_shmtx_lock(&shpool->mutex);
    ngx_rbtree_delete(ngx_http_hostprotect_rbtree, root->left);
    ngx_shmtx_unlock(&shpool->mutex);
    i++;
  }

  while(root->right != NULL) {
    ngx_shmtx_lock(&shpool->mutex);
    ngx_rbtree_delete(ngx_http_hostprotect_rbtree, root->right);
    ngx_shmtx_unlock(&shpool->mutex);
    j++;
  }
}

void inline __attribute__((always_inline)) swap_bytes(unsigned char *orig, unsigned char *changed)
{
  int i = 3;
  int j;
  char *tmp[4] = {0};
  char *t = strtok(strndup(orig, 15), ".");

  while(t != NULL) {
    tmp[i--] = t;
    t = strtok(NULL, ".");
  }

  for(j = 0; j < 4; j++) {
    if(tmp[j] != NULL) {
      strcat(changed, tmp[j]);
      strcat(changed, ".");
    }
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
  memset(host, 0, sizeof(host));
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
      if(bytes_recv) {
        /* if debug */
        if(conf->debug)
          ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "%s: %d bytes received from server for %s", MODULE_NAME, bytes_recv, ip);

        if(bytes_recv > 80)
          goto err_go;

        qname = (unsigned char*)&buf[sizeof(struct dns_header)];
        reader = &buf[sizeof(struct dns_header) + (strlen(qname)+1) + sizeof(struct dns_question)];
      }
    }
  }

  ans = (struct dns_answer *)reader;
  if(ans != NULL) {
    int size_a = ntohs(ans->rdlength);
    ans->data = (unsigned char *) malloc(size_a);
    for(j; j < size_a; j++)
      ans->data[j] = reader[j];

    if(ans->data[p++] == '1' && ans->data[++p] == 'b')
      *status = 1;
  }

  err_go:
    /* don't forget to close the socket, because you will reach socket limit by pid */
    close(s);
    return;

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
