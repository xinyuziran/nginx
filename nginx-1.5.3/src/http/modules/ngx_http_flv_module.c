
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

//flashapp
typedef struct ngx_http_flv_param_s  ngx_http_flv_param_t;

struct ngx_http_flv_param_s {
	ngx_str_t domain;
	ngx_str_t start;
	ngx_str_t end;
	ngx_str_t starttime;
	ngx_str_t endtime;
	ngx_str_t uri;//
	ngx_uint_t flag;//0 normal size drag 1 time  drag
	ngx_uint_t specal_flag;// 1 暴力拖拽忽略13
};

typedef struct {
    ngx_array_t                  *params;
    ngx_uint_t                   flag;
} ngx_http_flv_loc_conf_t;

///flv 结构
/*
 * FLV文件头结构，占用9个字节
 */
typedef struct
{
	/* 第1-3字节为文件标识，总为"FLV",（0x46,0x4C,0x56）*/
	unsigned char signature[3];
	/* 第4个字节为版本，目前为0x01 */
	unsigned char version;
	/*
	 * 第五个字节第5个字节的前5位保留，必须为0。
	 * 第5个字节的第6位表示是否存在音频Tag。
	 * 第5个字节的第7位保留，必须为0。
	 * 第5个字节的第8位表示是否存在视频Tag。
	 */
	unsigned char flags;
	/* 第6-9字节表示从File Header开始到File Body开始的字节数，版本1中总为9。*/
	unsigned char headersize[4];
} ngx_http_flv_file_header_t;

/*
 * FLV Tag结构，占用11个字节
 * Tag包括Tag Header和Tag Data两部分。
 * 不同类型的Tag的Header结构是相同的，但是Data结构各不相同。
 */
typedef struct
{
	/* 第1个字节表示Tag类型，包括音频（0x08）、视频（0x09）和script data（0x12），其他类型值被保留。*/
	unsigned char type;
	/* 第2-4字节为UI24类型的值，表示该Tag Data部分的大小。*/
	unsigned char datasize[3];
	/* 第5-7字节为UI24类型的值，表示该Tag的时间戳（单位为ms），第一个Tag的时间戳总是0。*/
	unsigned char timestamp[3];
	/* 第8个字节为时间戳的扩展字节，当24位数值不够时，该字节作为最高位将时间戳扩展为32位值。*/
	unsigned char timestamp_ex;
	/* 第9-11字节为UI24类型的值，表示stream id，总是0。*/
	unsigned char streamid[3];
} ngx_http_flv_file_tag_t;


/*
 * video Tag data结构
 * 视频Tag也用开始的第1个字节包含视频数据的参数信息，从第2个字节开始为视频流数据。
 * 第1个字节的前4位的数值表示帧类型。
 * 第1个字节的后4位的数值表示视频编码ID，
 *  1 = JPEG（现已不用），				2 = Sorenson H.263，
 *  3 = Screen video，					4 = On2 VP6，
 *  5 = On2 VP6 with alpha channel，		6 = Screen video version 2。
 */
typedef struct
{
	unsigned char flags;
} ngx_http_flv_video_data_t;

typedef char ngx_http_flv_video_stream_t;

//默认参数
static ngx_str_t ngx_flv_para_start = ngx_string("start");
static ngx_str_t ngx_flv_para_end = ngx_string("end");
static ngx_str_t ngx_flv_para_starttime = ngx_string("starttime");
static ngx_str_t ngx_flv_para_endtime = ngx_string("endtime");

static void *ngx_http_flv_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_flv_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *
ngx_http_flv_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
		void *conf);

static ngx_int_t
ngx_http_flv_get_param(ngx_http_request_t *r,ngx_http_flv_param_t *param);

static ngx_int_t
ngx_http_flv_get_start_end(ngx_http_request_t *r,ngx_http_flv_param_t *param,
		off_t *s ,off_t *e);

static ngx_int_t
ngx_http_flv_is_right_file(ngx_open_file_info_t  *of);

static ngx_int_t
ngx_http_flv_find_keyframe_by_normal(ngx_http_request_t *r,ngx_open_file_info_t  *of,
		ngx_chain_t **out ,ngx_str_t path,off_t* datalen, off_t start, off_t end, int flag);

static ngx_int_t
ngx_http_flv_find_keyframe_by_adobe(ngx_http_request_t *r,ngx_open_file_info_t  *of,
		ngx_chain_t **out ,ngx_str_t path,off_t* datalen, off_t start, off_t end, int flag);

static char *ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_flv_commands[] = {

    { ngx_string("flv"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_flv,
      0,
      0,
      NULL },
     { ngx_string("flv_param"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_flv_param_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

//////////////////////////*************************************//////
//static u_char  ngx_flv_header[]  = "FLV\x1\x5\0\0\0\x9\0\0\0\0";
static u_char  ngx_flv_headerc[] = "CCC\x1\x1\0\0\0\x9\0\0\0\x9";
static u_char  ngx_flv_headerv[] = "FLV\x1\x1\0\0\0\x9\0\0\0\x9";
static u_char  ngx_flv_headerav[]  = "FLV\x1\x5\0\0\0\x9\0\0\0\x9";

#define FLV_UI32(x) (int)(((x[0]) << 24) + ((x[1]) << 16) + ((x[2]) << 8) + (x[3]))
#define FLV_UI24(x) (int)(((x[0]) << 16) + ((x[1]) << 8) + (x[2]))
#define FLV_UI16(x) (int)(((x[0]) << 8) + (x[1]))
#define FLV_UI8(x) (int)((x))

#define FLV_AUDIODATA	8
#define FLV_VIDEODATA	9
#define FLV_SCRIPTDATAOBJECT	18

#define FLV_H263VIDEOPACKET	2
#define FLV_SCREENVIDEOPACKET	3
#define	FLV_VP6VIDEOPACKET	4
#define	FLV_VP6ALPHAVIDEOPACKET	5
#define FLV_SCREENV2VIDEOPACKET	6

/////////////////////*********************************///////////////////////
static ngx_http_module_t  ngx_http_flv_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_flv_create_loc_conf,  /* create location configuration */
    ngx_http_flv_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_flv_module = {
    NGX_MODULE_V1,
    &ngx_http_flv_module_ctx,      /* module context */
    ngx_http_flv_commands,         /* module directives */
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


static ngx_int_t
ngx_http_flv_handler(ngx_http_request_t *r)
{
    u_char                    *last;
    off_t                      start, end,len;
    size_t                     root;
    ngx_int_t                  rc,flag;
    ngx_uint_t                 level;
//    ngx_uint_t                 i;
    ngx_str_t                  path;
//    ngx_str_t				   value;
    ngx_log_t                 *log;
//    ngx_buf_t                 *b;
//    ngx_chain_t                out[2];
    ngx_chain_t                *pout=NULL;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_flv_param_t      flvparam;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (ngx_close_file(of.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                          ngx_close_file_n " \"%s\" failed", path.data);
        }

        return NGX_DECLINED;
    }

    r->root_tested = !r->error_page;

    start = 0;
    len = of.size;
    end = 0;
//    i = 1;
    flag=1;

    if (r->args.len) {
    	if(ngx_http_flv_is_right_file(&of) >0){
    		ngx_http_flv_get_param(r,&flvparam);
    		flag=ngx_http_flv_get_start_end(r,&flvparam,&start,&end);
    	}
/*
        if (ngx_http_arg(r, (u_char *) "start", 5, &value) == NGX_OK) {

            start = ngx_atoof(value.data, value.len);

            if (start == NGX_ERROR || start >= len) {
                start = 0;
            }

            if (start) {
                len = sizeof(ngx_flv_header) - 1 + len - start;
                i = 0;
            }
        }
        */
    }

	if(ngx_http_flv_find_keyframe_by_normal(r,&of,&pout,path,&len,start,end,flag) <=0){
		ngx_http_flv_find_keyframe_by_adobe(r,&of,&pout,path,&len,start,end,flag);
	}


    log->action = "sending flv to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
/*
    if (i == 0) {
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->pos = ngx_flv_header;
        b->last = ngx_flv_header + sizeof(ngx_flv_header) - 1;
        b->memory = 1;

        out[0].buf = b;
        out[0].next = &out[1];
    }


    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
*/
    r->allow_ranges = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
/*
    b->file_pos = start;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out[1].buf = b;
    out[1].next = NULL;
*/
 //   return ngx_http_output_filter(r, &out[i]);
    return ngx_http_output_filter(r,pout);
}


static char *
ngx_http_flv(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_flv_handler;

    return NGX_CONF_OK;
}

//flashapp
static void *
ngx_http_flv_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_flv_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_flv_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->params = NGX_CONF_UNSET_PTR;
    conf->flag = NGX_CONF_UNSET_UINT;


    return conf;
}

static char *
ngx_http_flv_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flv_loc_conf_t *prev = parent;
    ngx_http_flv_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->flag,prev->flag, 0);

    ngx_conf_merge_ptr_value(conf->params,prev->params, NULL);

    return NGX_CONF_OK;
}

static char *
ngx_http_flv_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_uint_t              i;
    ngx_str_t               *value;
    ngx_http_flv_param_t    *pa;
    ngx_http_flv_loc_conf_t *flcf = conf;
    ngx_int_t 				n;

    if(flcf->params == NULL){
    	return NGX_CONF_OK;
    }

    if(cf->args->nelts < 2){
    	return NGX_CONF_ERROR;
    }

    if (flcf->params == NGX_CONF_UNSET_PTR) {
    	flcf->params = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_http_flv_param_t));
        if (flcf->params == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    pa = ngx_array_push(flcf->params);

    if (pa == NULL) {
    	return NGX_CONF_ERROR;
    }else{
    	ngx_memset(pa,0,sizeof(ngx_http_flv_param_t));
    	pa->start = ngx_flv_para_start;
    	pa->end = ngx_flv_para_end;
    	pa->starttime = ngx_flv_para_starttime;
    	pa->endtime = ngx_flv_para_endtime;
    }

    value = cf->args->elts;

    pa->domain = value[1];

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "start=", 6) == 0) {
        	pa->start.data = value[i].data + 6;
        	pa->start.len = value[i].len - 6;
        	continue;
        }

        if (ngx_strncmp(value[i].data, "end=", 4) == 0) {
        	pa->end.data = value[i].data + 4;
            pa->end.len = value[i].len - 4;
            continue;
        }

        if (ngx_strncmp(value[i].data, "starttime=", 10) == 0) {
        	pa->starttime.data = value[i].data + 10;
            pa->starttime.len = value[i].len - 10;
            continue;
        }

        if (ngx_strncmp(value[i].data, "endtime=", 8) == 0) {
        	pa->endtime.data = value[i].data + 8;
            pa->endtime.len = value[i].len - 8;
            continue;
        }

        if (ngx_strncmp(value[i].data, "uri=", 4) == 0) {
        	pa->uri.data = value[i].data + 4;
            pa->uri.len = value[i].len - 4;
            continue;
        }

        if (ngx_strncmp(value[i].data, "flag=",5) == 0) {
        	 n = ngx_atoi(value[i].data + 5, value[i].len - 5);
        	if (n == NGX_ERROR) {
        		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        				"invalid flag value \"%V\"", &value[i]);
        		return NGX_CONF_ERROR;
        	}
        	pa->flag= n;

            continue;
        }

        if (ngx_strncmp(value[i].data, "specal_flag=",12) == 0) {
        	 n = ngx_atoi(value[i].data + 12, value[i].len - 12);
        	if (n == NGX_ERROR) {
        		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        				"invalid flag value \"%V\"", &value[i]);
        		return NGX_CONF_ERROR;
        	}
        	pa->specal_flag = n;

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_flv_get_param(ngx_http_request_t *r,ngx_http_flv_param_t *param)
{
	ngx_int_t				  rc = NGX_OK;
	ngx_uint_t                 i;
	ngx_http_flv_param_t       **params;
	ngx_str_t 				   host,uri;
	ngx_http_flv_loc_conf_t   *flcf;
	ngx_http_core_srv_conf_t  *cscf;

	flcf = ngx_http_get_module_loc_conf(r, ngx_http_flv_module);
	cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    if (r->headers_in.server.len) {
        host = r->headers_in.server;
    } else {
    	host = cscf->server_name;
    }

    uri = r->unparsed_uri;

    param->domain = host;
    param->start = ngx_flv_para_start;
    param->end = ngx_flv_para_end;
    param->starttime = ngx_flv_para_starttime;
    param->endtime = ngx_flv_para_endtime;
    param->flag =0;
    param->specal_flag =0;
    param->uri = r->unparsed_uri;

    if(flcf->params){
    	params = flcf->params->elts;
    	for(i=0;i< flcf->params->nelts;i++) {
    		if((params[i]->domain.data !=NULL) && (ngx_strstr(host.data, params[i]->domain.data) != NULL)){
    			if(params[i]->uri.data !=NULL){
    				if(ngx_strstr(uri.data, params[i]->uri.data) != NULL){
    					param = params[i];
    				}
    			}else{
    				param = params[i];
    			}
    		}
    	}
    }
    return rc;
}


static ngx_int_t
ngx_http_flv_get_start_end(ngx_http_request_t *r,ngx_http_flv_param_t *param,off_t *s ,off_t *e)
{
	off_t                      start =-1, end =-1;// -1 为没设置
	ngx_str_t 				   value;
	ngx_int_t				   rc =0;

	if (ngx_http_arg(r, param->start.data , param->start.len, &value) == NGX_OK) {
		start = ngx_atoof(value.data, value.len);
    	if (start == NGX_ERROR) {
    		start = 0;
    	}
    	rc =1;
        if (ngx_http_arg(r, param->end.data , param->end.len, &value) == NGX_OK) {
        	end = ngx_atoof(value.data, value.len);
        	if (end == NGX_ERROR) {
        		end = 0;
        	}
        	rc =1;
        }
    }

    if (ngx_http_arg(r, param->starttime.data , param->starttime.len, &value) == NGX_OK) {
    	if((param->flag == 1)||(start == -1)){
    		start = ngx_atoof(value.data, value.len);
    		if (start == NGX_ERROR) {
    			start = 0;
    		}
    		rc =2;
    	}

        if (ngx_http_arg(r, param->endtime.data , param->endtime.len, &value) == NGX_OK) {
        	if((param->flag == 1)||(end == -1)){
        		end = ngx_atoof(value.data, value.len);
        		if (end == NGX_ERROR) {
        			end = 0;
        		}
        		rc =2;
        	}
        }
    }

    if(start <0){
    	start =0;
    }
    if(end <0){
    	end =0;
    }

    *s =start;
    *e =end;
	return rc;
}

static ngx_int_t
ngx_http_flv_is_right_file(ngx_open_file_info_t  *of)
{
	ngx_int_t ftype = 0;
	char * flv =NULL;
	if(of->fd!= NGX_INVALID_FILE)
	{
		flv = mmap(NULL, of->size, PROT_READ, MAP_PRIVATE, of->fd, 0);
		if(flv == NULL)
		{
			return ftype;
		}
		if(strncmp(flv, "CCC", 3) == 0){
			ftype =1;
		}else if(strncmp(flv, "FLV", 3) == 0){
			ftype =2;
		}
		munmap(flv, of->size);
	}

	return ftype;
}


u_char * flv_strstr(u_char *src,u_char *substr,u_int srclen)
{
	u_char *tmpstr,*pstr=0;
	tmpstr = src;
	while(!(pstr = (u_char *)strstr((const char*)tmpstr,(const char*)substr)) ){
		tmpstr = tmpstr + strlen((const char*)tmpstr);
		if( (u_int)( tmpstr -src) >= srclen ) return NULL;
		while( strlen((const char*)tmpstr) == 0 ){
			tmpstr ++;
			if((u_int)( tmpstr - src) >= srclen) return NULL;
		}
	}
	return pstr;
}

double double_swap(u_char *str)
{
	u_char *ptr = 0;
	double ret=0;
	u_char *tmp=(u_char *)(&ret);
	ptr=str;
	int i = 7;
	for(;i >= 0;i--)
	{
		*tmp=*(ptr+i);
		tmp++;
	}
	return ret;
}

#define MAX_SEND_CHAIN 10

static ngx_int_t
ngx_http_flv_find_keyframe_by_normal(ngx_http_request_t *r,ngx_open_file_info_t  *of,
		ngx_chain_t **out ,ngx_str_t path,off_t* datalen, off_t start, off_t end, int flag/* 1长度 2 时间*/)
{
	ngx_http_flv_file_header_t *ffh = NULL;
	ngx_http_flv_file_tag_t*  tag =NULL;
	ngx_int_t rc=NGX_ERROR, hasa =0 ,ftype = 0,count_of_file=0,count_of_times=0;
	off_t filesize= 0;
	double streampos_start ,streampos_end ,streampos ,datasize ;
	char* data=NULL ,*flv=NULL;
	u_char *keyframes =NULL,*filepositions =NULL,*times=NULL;
	double *filepositions_arr = NULL,*times_arr =NULL ,*pcompare=NULL;

	off_t len=0;
	ngx_int_t ichain =0;
	ngx_buf_t *b=NULL;
	ngx_chain_t *out_chain=NULL;
	out_chain=ngx_palloc(r->pool,(MAX_SEND_CHAIN+1)*sizeof(ngx_chain_t));

	if(out_chain==NULL){
		return NGX_ERROR;
	}

	if(of->fd== NGX_INVALID_FILE){
		return rc;
	}

	filesize = of->size;
	streampos_start=13;
	streampos_end =filesize;

	flv= mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, of->fd, 0);
	if(flv == NULL){
		return rc;
	}

	rc= 0;

	/*判断文件类型*/
	if(strncmp(flv, "CCC", 3) == 0){
		ftype =1;
	}else if(strncmp(flv, "FLV", 3) == 0){
		ftype =2;
	}

	//读取头
	ffh = (ngx_http_flv_file_header_t *)flv;
	if(ffh ==NULL){
		goto done;
	}

	/*判断文件里是否有音频*/
	if(ffh->flags == 5){
		hasa = 1;
	}else if(ffh->flags == 1){
		hasa = 0;
	}

	/* 初始化发送头 */
	b =ngx_calloc_buf(r->pool);
	if(b==NULL){
		return NGX_ERROR;
	}
	if(ftype == 1){
		b->pos = ngx_flv_headerc;
		b->last = ngx_flv_headerc + sizeof(ngx_flv_headerc) - 1;
		b->memory = 1;
	}else{
		if(hasa==1){
			b->pos = ngx_flv_headerav;
			b->last = ngx_flv_headerav + sizeof(ngx_flv_headerav) - 1;
			b->memory = 1;
		}else{
			b->pos = ngx_flv_headerv;
			b->last = ngx_flv_headerv + sizeof(ngx_flv_headerv) - 1;
			b->memory = 1;
		}
	}
	len =b->last -b->pos;
	out_chain[ichain].buf=b;
	if(ichain +1>= MAX_SEND_CHAIN){
		out_chain[ichain].next=NULL;
		goto done;
	}
	out_chain[ichain].next=&out_chain[ichain+1];
	ichain++;

	if((end>0) && (start > end)){
		goto done;
	}

	streampos = FLV_UI32(ffh->headersize) + 4;

	if(streampos > filesize){
		goto done;
	}
	/* 读取控制帧的header */
	tag = (ngx_http_flv_file_tag_t*)&flv[(int64_t)streampos];
	if(tag ==NULL){
		goto done;
	}
	/* 该控制帧的大小 = tag header大小 + tag data大小 + 4字节 */
	datasize = sizeof(ngx_http_flv_file_tag_t) + FLV_UI24(tag->datasize) + 4;
	/* flvmetadata指向控制帧的 tag data */
	data= (char*)&flv[(int64_t)streampos+sizeof(ngx_http_flv_file_tag_t)];
	//在字符串flvmetadata中查找"keyframes"第一次出现的位置
	keyframes=flv_strstr((u_char*)data,(u_char*)"keyframes",datasize -sizeof(ngx_http_flv_file_tag_t) - 4);
	if(keyframes ==NULL){
		goto done;
	}

	rc =1;

	/* 获取关键帧的大小数据 */
	filepositions=flv_strstr(keyframes,(u_char*)"filepositions",datasize - sizeof(ngx_http_flv_file_tag_t) - 4);
	if(NULL==filepositions){
		goto done;
	}

	/* 获取关键帧的时间数据 */
	times=flv_strstr(keyframes,(u_char*)"times",datasize - sizeof(ngx_http_flv_file_tag_t) -4);
	if(times==NULL){
		goto done;
	}

	if(((char *)filepositions + 14 - flv) > filesize || ((char *)times + 6 - flv) > filesize){
		goto done;
	}
	filepositions += 14;
	times += 6;

	count_of_file = FLV_UI32(filepositions);
	count_of_times = FLV_UI32(times);

	int tmp_count = 0;

	if(count_of_file != count_of_times)
	{
		tmp_count = (count_of_file < count_of_times ? count_of_file : count_of_times);
		count_of_file = tmp_count;
		count_of_times = tmp_count;
	}

	filepositions_arr = (double *)ngx_palloc(r->pool,sizeof(double) * count_of_file);
	if(filepositions_arr==NULL){
		goto done;
	}

	times_arr = (double *)ngx_palloc(r->pool,sizeof(double) * count_of_file);
	if(times_arr==NULL){
		goto done;
	}

	if(((char *)filepositions + 5 - flv) > filesize || ((char *)times + 5 - flv) > filesize){
		goto done;
	}
	filepositions+=5;
	times+=5;

	int index_tag = 0;
	for(index_tag = 0;index_tag < count_of_file;index_tag++)
	{
		filepositions_arr[index_tag] = double_swap(filepositions);
		times_arr[index_tag] = double_swap(times);
		if(((char *)filepositions + 9 - flv) > filesize || ((char *)times + 9 - flv) > filesize){
			goto done;
		}
		times+=9;
		filepositions+=9;
	}

	int index_loop = 0;
	for(;index_loop<3;index_loop++){
		if(streampos > filesize){
			goto done;
		}
		tag = (ngx_http_flv_file_tag_t*)&flv[(int64_t)streampos];
		if(tag == NULL){
			goto done;
		}
		datasize = sizeof(ngx_http_flv_file_tag_t) + FLV_UI24(tag->datasize) + 4;

		if(ftype != 1){
#if NO_CTRL_FLAG_BITE
			//丢弃控制帧
			if(index_loop != 0){
				/*增加if判断后去掉视频前面的控制帧，否则在视频前面添加控制帧*/
#endif
				b =ngx_calloc_buf(r->pool);
				if(b==NULL){
					return NGX_ERROR;
				}
				b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
			    b->file_pos = streampos;
			    b->file_last = streampos+datasize;
			    b->in_file = b->file_last ? 1: 0;

			    b->file->fd = of->fd;
			    b->file->name = path;
			    b->file->log = r->connection->log;
			    b->file->directio = of->is_directio;
			    len =len+datasize;
				out_chain[ichain].buf =b;
				if(ichain +1>= MAX_SEND_CHAIN){
					out_chain[ichain].next=NULL;
					goto done;
				}
				out_chain[ichain].next=&out_chain[ichain+1];
				ichain++;
#if NO_CTRL_FLAG_BITE
			}
#endif
		}
		streampos += datasize;
	}

	streampos_start = streampos;

	if(flag==1){//大小
		pcompare=filepositions_arr;
	}else{//时间
		pcompare=times_arr;
	}

	if(start > pcompare[count_of_file-1]){
		streampos_start=(double)filepositions_arr[count_of_file-1];
		goto done;
	}

	for(index_tag = 0; index_tag < count_of_file - 1 ; index_tag++)
	{
		if((pcompare[index_tag] <= start)&&(pcompare[index_tag + 1] >= start))
		{
			streampos_start=(double)filepositions_arr[index_tag];
			if(end<=0){
				break;
			}
		}

		if((end>0)&&(index_tag>0)){
			if(pcompare[index_tag] >= end)
			{
				if(filepositions_arr[index_tag - 1] > streampos_start){
					streampos_end = (double)filepositions_arr[index_tag - 1];
					break;
				}
			}
		}
	}

done:
//修正
	if(streampos_start >= filesize){
		streampos_start=13;
	}
	if(streampos_end >= filesize){
		streampos_end=filesize;
	}

	if(streampos_start >= streampos_end){
		if(end > start){
			streampos_end=streampos_start+end-start;
		}else{
			streampos_end=filesize;
		}
	}

	b =ngx_calloc_buf(r->pool);
	if(b==NULL){
		return NGX_ERROR;
	}
	b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));

	b->file_pos = streampos_start;
	b->file_last = streampos_end;

	b->in_file = b->file_last ? 1: 0;
	b->last_buf = (r == r->main) ? 1 : 0;
	b->last_in_chain = 1;

	b->file->fd = of->fd;
	b->file->name = path;
	b->file->log = r->connection->log;
	b->file->directio = of->is_directio;
	len=len+streampos_end-streampos_start;
	*datalen=len;
	out_chain[ichain].buf=b;
	out_chain[ichain].next= NULL;
	*out=&out_chain[0];
	munmap(flv, filesize);

	return rc;
}

static ngx_int_t
ngx_http_flv_find_keyframe_by_adobe(ngx_http_request_t *r, ngx_open_file_info_t  *of,
		ngx_chain_t **out ,ngx_str_t path,off_t* datalen, off_t start, off_t end, int flag/* 1长度 2 时间*/)
{
	ngx_http_flv_file_header_t *ffh = NULL;
	ngx_http_flv_file_tag_t*  tag =NULL;
	ngx_http_flv_video_data_t* fvideo =NULL;
	ngx_int_t ftype = 0, hasa =0 ,checkstart =0/* 1 检查开始  2  检查结束 3 完成*/;
	off_t filesize= 0 ,check_tmp=0;
	double streampos  ,datasize, streampos_start ,streampos_end, compare_data;;
	char *flv =NULL;
	off_t len=0;

	ngx_int_t ichain =0;
	ngx_buf_t *b=NULL;
	ngx_chain_t *out_chain=NULL;
	out_chain=ngx_palloc(r->pool,(MAX_SEND_CHAIN+1)*sizeof(ngx_chain_t));

	if(out_chain==NULL){
		return NGX_ERROR;
	}

	if(of->fd== NGX_INVALID_FILE){
		return NGX_ERROR;
	}

	filesize = of->size;
	streampos_start=13;
	streampos_end =filesize;

	flv= mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, of->fd, 0);
	if(flv == NULL){
		return NGX_ERROR;
	}

	/*判断文件类型*/
	if(strncmp(flv, "CCC", 3) == 0){
		ftype =1;
	}else if(strncmp(flv, "FLV", 3) == 0){
		ftype =2;
	}

	//读取头
	ffh = (ngx_http_flv_file_header_t *)flv;
	if(ffh ==NULL){
		goto done;
	}
	/*判断文件里是否有音频*/
	if(ffh->flags == 5){
		hasa = 1;
	}else if(ffh->flags == 1){
		hasa = 0;
	}

	/* 初始化发送头 */
	b =ngx_calloc_buf(r->pool);
	if(b==NULL){
		return NGX_ERROR;
	}
	if(ftype == 1){
		b->pos = ngx_flv_headerc;
		b->last = ngx_flv_headerc + sizeof(ngx_flv_headerc) - 1;
		b->memory = 1;
	}else{
		if(hasa==1){
			b->pos = ngx_flv_headerav;
			b->last = ngx_flv_headerav + sizeof(ngx_flv_headerav) - 1;
			b->memory = 1;
		}else{
			b->pos = ngx_flv_headerv;
			b->last = ngx_flv_headerv + sizeof(ngx_flv_headerv) - 1;
			b->memory = 1;
		}
	}
	len =b->last- b->pos;
	out_chain[ichain].buf=b;
	if(ichain +1>= MAX_SEND_CHAIN){
		out_chain[ichain].next=NULL;
		goto done;
	}
	out_chain[ichain].next=&out_chain[ichain+1];
	ichain++;

	if((end>0) && (start > end)){
		goto done;
	}

	streampos = FLV_UI32(ffh->headersize) + 4;
	if(streampos > filesize){
		goto done;
	}

	int index_loop = 0;
	for(;index_loop<3;index_loop++){
		if(streampos > filesize){
			goto done;
		}
		tag = (ngx_http_flv_file_tag_t*)&flv[(int64_t)streampos];
		if(tag == NULL){
			goto done;
		}
		datasize = sizeof(ngx_http_flv_file_tag_t) + FLV_UI24(tag->datasize) + 4;

		if(ftype != 1){
#if NO_CTRL_FLAG_BITE
			//丢弃控制帧
			if(index_loop != 0){
				/*增加if判断后去掉视频前面的控制帧，否则在视频前面添加控制帧*/
#endif
				b =ngx_calloc_buf(r->pool);
				if(b==NULL){
					return NGX_ERROR;
				}
				b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));

			    b->file_pos = streampos;
			    b->file_last = streampos+datasize;
			    b->in_file = b->file_last ? 1: 0;

			    b->file->fd = of->fd;
			    b->file->name = path;
			    b->file->log = r->connection->log;
			    b->file->directio = of->is_directio;
			    len =len+datasize;
				out_chain[ichain].buf=b;
				if(ichain +1>= MAX_SEND_CHAIN){
					out_chain[ichain].next=NULL;
					goto done;
				}
				out_chain[ichain].next=&out_chain[ichain+1];
				ichain++;
#if NO_CTRL_FLAG_BITE
			}
#endif
		}
		streampos += datasize;
	}

	streampos_start =streampos;

	if(start>0){
		check_tmp =start;
		checkstart= 1;
		while(streampos < filesize){
			tag = (ngx_http_flv_file_tag_t*)&flv[(int64_t)streampos];
			if(tag == NULL){
				goto done;
			}
			// TagHeader + TagData + PreviousTagSize
			datasize = sizeof(ngx_http_flv_file_tag_t) + FLV_UI24(tag->datasize) + 4;
			if(flag ==1){//大小
				compare_data =streampos;
			}else{//时间
				compare_data =(double)((tag->timestamp_ex << 24) + (tag->timestamp[0] << 16) +
						(tag->timestamp[1] << 8) + tag->timestamp[2]) / 1000.0;
			}
			if(compare_data >= check_tmp){
				if(tag->type == FLV_VIDEODATA){
					fvideo = (ngx_http_flv_video_data_t *)&flv[(int64_t)streampos
				                                        + sizeof(ngx_http_flv_file_tag_t)];
					if(fvideo ==NULL){
						goto done;
					}

					// 判断关键帧
					if(((fvideo->flags >> 4) & 1) == 1){
						double tmp_stream = streampos;
						if(hasa==0){//没有音频
							goto check;
						}

						streampos += datasize;
						if(streampos > filesize){
							goto done;
						}
						tag = (ngx_http_flv_file_tag_t*)&flv[(int64_t)streampos];
						if(tag == NULL){
							goto done;
						}
						if(tag->type == FLV_AUDIODATA){
check:						if(checkstart ==1){
								streampos_start = tmp_stream;
								if(end > 0){
									check_tmp=end;
									checkstart =2;
								}else{
									checkstart =3;
									break;
								}
							}else if(checkstart ==2){
								streampos_end = tmp_stream;
								checkstart =3;
								break;
							}
						}
						datasize = sizeof(ngx_http_flv_file_tag_t) + FLV_UI24(tag->datasize) + 4;
					}
				}
			}
			streampos += datasize;
		}
//正常结束
	}
done:

//修正
	if(streampos_start >= filesize){
		streampos_start=13;
	}
	if(streampos_end >= filesize){
		streampos_end=filesize;
	}

	if(streampos_start >= streampos_end){
		if(end > start){
			streampos_end=streampos_start+end-start;
		}else{
			streampos_end=filesize;
		}
	}

	b =ngx_calloc_buf(r->pool);
	if(b==NULL){
		return NGX_ERROR;
	}

	b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));

    b->file_pos = streampos_start;
    b->file_last = streampos_end;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of->fd;
    b->file->name = path;
    b->file->log = r->connection->log;
    b->file->directio = of->is_directio;
    len=len+streampos_end-streampos_start;
    *datalen =len;
	out_chain[ichain].buf=b;
	out_chain[ichain].next= NULL;
	*out=&out_chain[0];
	munmap((void*)flv, (size_t)filesize);
	return NGX_OK;
}
