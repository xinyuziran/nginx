/*
 * nginx (c) Igor Sysoev
 * this module (C) Mykola Grechukh <gns@altlinux.org>
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif

#define NGX_KUWO_MD5 1
#define NGX_KUWO_SHA1 2

typedef struct {
    ngx_flag_t    enable;
    ngx_uint_t    hashmethod;
    ngx_str_t     signature;
    ngx_str_t     host;
    ngx_str_t     uri;
    ngx_http_regex_t     *hostregex;
    ngx_http_regex_t     *urlregex;
} ngx_http_kuwo_loc_conf_t;

static ngx_str_t  ngx_kuwo_signature = ngx_string("kuwo_web@1906");
static ngx_str_t  ngx_kuwo_url = ngx_string("^.*/(.{32})/(.{8})/resource(.*)");
static ngx_str_t  ngx_kuwo_host = ngx_string("^.*sycdn\\.kuwo\\.cn");

static ngx_int_t ngx_http_kuwo_handler(ngx_http_request_t *r);

static char *ngx_http_kuwo_hashmethod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_kuwo_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_kuwo_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_kuwo_init(ngx_conf_t *cf);

static ngx_command_t  ngx_http_kuwo_commands[] = {
    { ngx_string("kuwo"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_kuwo_loc_conf_t, enable),
      NULL },

    { ngx_string("kuwo_hashmethod"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_kuwo_hashmethod,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("kuwo_signature"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_kuwo_loc_conf_t, signature),
      NULL},

    { ngx_string("kuwo_host"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_kuwo_loc_conf_t, host),
      NULL},

    { ngx_string("kuwo_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_kuwo_loc_conf_t, uri),
      NULL},

      ngx_null_command
};


static ngx_http_module_t  ngx_http_kuwo_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_kuwo_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_kuwo_create_loc_conf,       /* create location configuration */
    ngx_http_kuwo_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_kuwo_module = {
    NGX_MODULE_V1,
    &ngx_http_kuwo_module_ctx,           /* module context */
    ngx_http_kuwo_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static time_t
strtotime(u_char * p,ngx_uint_t len)
{
	time_t ct=0;
	ngx_uint_t n=0,i=0;
	for(i=0;i<len;i++){
		if(p[i]>='A'&&p[i]<='F')
			n=p[i]-'A'+10;
		else if(p[i]>='a'&&p[i]<='f')
		    n=p[i]-'a'+10;
		else n=p[i]-'0';
		ct=ct*16+n;
	}
	return ct;
}


static ngx_int_t
ngx_http_kuwo_handler(ngx_http_request_t *r)
{
    ngx_uint_t   hashlength,bhashlength;
    ngx_http_kuwo_loc_conf_t  *alcf;
    u_char hashb[64]={0}, hasht[128]={0};
    u_char checktime[9]={0},checkt[33]={0};
    static u_char hex[] = "0123456789abcdef";
    u_char val[1024]={0},ft[1024]={0};
    ngx_uint_t  vallen=0;
    ngx_uint_t   i;
    MD5_CTX md5;
    SHA_CTX sha;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_kuwo_module);

    if (!alcf->enable) {
        return NGX_OK;
    }
    switch(alcf->hashmethod) {
        case NGX_KUWO_SHA1:
            bhashlength=20;
            break;

	case NGX_KUWO_MD5:
            bhashlength=16;
            break;
        default: 
           ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
               "kuwo: hash not supported");
           return NGX_HTTP_FORBIDDEN;
    }
    hashlength=bhashlength*2;
    if((alcf->hostregex !=NULL) && (alcf->urlregex !=NULL)){
    	 if (ngx_http_regex_exec(r, alcf->hostregex, &(r->headers_in.server)) != NGX_OK){
    		 return NGX_OK;
    	 }else{
    		 if (ngx_http_regex_exec(r, alcf->urlregex, &(r->unparsed_uri)) != NGX_OK){
    			 return NGX_OK;
    		 }else{
    			 ngx_cpystrn(checkt,r->unparsed_uri.data+1,33);
    			 ngx_cpystrn(checktime,r->unparsed_uri.data+34,9);
    			 ngx_cpystrn(ft,r->unparsed_uri.data+42,r->unparsed_uri.len-41);
    			 ngx_snprintf(val,1024,"%s%s%s",alcf->signature.data,ft,checktime);
    			 vallen=ngx_strlen(val);
    			 switch(alcf->hashmethod) {
    		     case NGX_KUWO_MD5:
    			      MD5Init(&md5);
    			      MD5Update(&md5,val,vallen);
    			      MD5Final(hashb, &md5);
    			      break;
    			 case NGX_KUWO_SHA1:
    			       SHA1_Init(&sha);
    			       SHA1_Update(&sha,val,vallen);
    			       SHA1_Final(hashb,&sha);
    			       break;
    			 };

    			    u_char *text = hasht;

    			    for (i = 0; i < bhashlength; i++) {
    			        *text++ = hex[hashb[i] >> 4];
    			        *text++ = hex[hashb[i] & 0xf];
    			    }

    			    *text = '\0';
    			    if (ngx_strncmp(hasht,checkt,hashlength)!=0){
    			            return NGX_HTTP_FORBIDDEN;
    			    }else{
    			    	time_t now = ngx_time();
    			    	time_t overtime=strtotime(checktime,8);
    			    	if(now > overtime){
    			    		return NGX_HTTP_UNAUTHORIZED;
    			    	}
    			    }
    		 }
    	 }
    }
    return NGX_OK;
}

static char *
ngx_http_kuwo_hashmethod(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *d = cf->args->elts;
    ngx_http_kuwo_loc_conf_t *alcf = conf;

    if ( (d[1].len == 3 ) && (ngx_strncmp(d[1].data,"md5",3) == 0) ) {
        alcf->hashmethod = NGX_KUWO_MD5;
    } else if ( (d[1].len == 4) && (ngx_strncmp(d[1].data,"sha1",4) == 0) ){
        alcf->hashmethod = NGX_KUWO_SHA1;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "kuwo_hashmethod should be md5 or sha1, not \"%V\"", d+1);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static void *
ngx_http_kuwo_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_kuwo_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_kuwo_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->hashmethod = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_kuwo_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_kuwo_loc_conf_t  *prev = parent;
    ngx_http_kuwo_loc_conf_t  *conf = child;
    ngx_regex_compile_t  hostrc,urlrc;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_uint_value(conf->hashmethod, prev->hashmethod, NGX_KUWO_MD5);;
    ngx_conf_merge_str_value(conf->signature,prev->signature,ngx_kuwo_signature.data);
    ngx_conf_merge_str_value(conf->host,prev->host,ngx_kuwo_host.data);
    ngx_conf_merge_str_value(conf->uri,prev->uri,ngx_kuwo_url.data);

    hostrc.pattern = conf->host;
    hostrc.options = NGX_REGEX_CASELESS;

    conf->hostregex = ngx_http_regex_compile(cf, &hostrc);

    urlrc.pattern = conf->uri;
    urlrc.options = NGX_REGEX_CASELESS;

    conf->urlregex = ngx_http_regex_compile(cf, &urlrc);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_kuwo_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_kuwo_handler;

    return NGX_OK;
}
