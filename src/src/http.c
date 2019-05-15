/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/* $Id$ */
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"
#include "util.h"
#include "wd_util.h"

#include "../config.h"
#include <openssl/e_os2.h>

#include "../../../openssl/openssl-0.9.8zh/crypto/md5/md5.h"
#include <time.h>
#include "list.h"

typedef struct
{
	char token_md5[64];
	char ip[16];					   
	char mac[20];  
	time_t last_active;
	struct list_head list;
}T_PRE_AUTH_INFO;

LIST_HEAD(gPreAuthList);

T_PRE_AUTH_INFO *pPreAuthClientCache = NULL;

static T_PRE_AUTH_INFO* find_in_pre_auth_list(const char* mac)
{
	T_PRE_AUTH_INFO* pos = NULL;
	T_PRE_AUTH_INFO* n = NULL;
	T_PRE_AUTH_INFO* ret = NULL;
	list_for_each_entry_safe(pos,n,&gPreAuthList,list)
	{
		if(!strncmp(pos->mac,mac? mac:"",strlen(mac)))
		{
			ret = pos;
			break;
		}
		
	}
	return ret;	
}

void del_in_pre_auth_list(const char* mac)
{
	T_PRE_AUTH_INFO* pos = NULL;
	T_PRE_AUTH_INFO* n = NULL;
	
	list_for_each_entry_safe(pos,n,&gPreAuthList,list)
	{
		if(!strncmp(pos->mac,mac? mac:"",strlen(mac)))
		{
			list_del_init(pos);
			if(pPreAuthClientCache == pos) pPreAuthClientCache = NULL;
			free(pos);
			break;
		}
		
	}
}


#define PRE_AUTH_CLIENT_TIMEOUT				300 

static void check_timeout_in_pre_auth_list()
{
	T_PRE_AUTH_INFO* pos = NULL;
	T_PRE_AUTH_INFO* n = NULL;
	list_for_each_entry_safe(pos,n,&gPreAuthList,list)
	{
	
		if((time(NULL) - pos->last_active) >= PRE_AUTH_CLIENT_TIMEOUT)
		{
			list_del_init(pos);
			if(pPreAuthClientCache == pos) pPreAuthClientCache = NULL;
			free(pos);
		}
		
	}
}

void insert_in_in_pre_auth_list(const char* mac,const char* ip,const char* md5)
{
	
	T_PRE_AUTH_INFO* ret = (T_PRE_AUTH_INFO*)malloc(sizeof(T_PRE_AUTH_INFO));
	if(ret != NULL)
	{	
		time(&ret->last_active);
		strncpy(ret->mac,mac?mac:"",strlen(mac));
		strncpy(ret->ip,ip?ip:"",strlen(ip));
		strncpy(ret->token_md5,md5?md5:"",strlen(md5));
		list_add(&ret->list, &gPreAuthList);
		pPreAuthClientCache = ret;
	}
	else
	{
		debug(LOG_INFO, "no enough memory to alloc T_PRE_AUTH_INFO objdect for ip %s mac %s",ip,mac);
	}
		
}

char Hex2Str(unsigned char dat,int idx)
{
    char temp = 0;
    if(idx)
        temp = dat>>4;
    else
        temp = dat&0xf;
    if(temp <= 9)
        return temp + '0';
    else
        return temp - 10 + 'a';     //全部转化为小写
    return 0;
}

void UnzipStr(char* dest,unsigned char* src,int destNum)
{
    int i = 0;
    for(i = 0;i < destNum;i++)
    {
        if(i%2)
            dest[i] = Hex2Str(src[i/2],0);
        else
            dest[i] = Hex2Str(src[i/2],1);
    }
}

int CalMd5(const char* szString, unsigned char* szMd5)
{
	MD5_CTX Ctx;

	MD5_Init(&Ctx);

	/* calculate md5 */
	MD5_Update(&Ctx, szString, strlen(szString));

	MD5_Final(szMd5, &Ctx);

return 0;
}


typedef struct 
{
	char token_md5[64];
	int hadPreAuth;
	int count;
	time_t date;
}ST_RRE_AUTH;

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{
    char tmp_url[MAX_BUF], *url, *mac;
    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();
	t_client *client, *tmp;
    t_authresponse auth_response = {0};
	char *token;
	unsigned char md5[16] = {0};
	char token_md5[64] = {0};
	char cmd[512];
	httpVar *var;
	FILE* fp = NULL;
	char *tid = NULL, *openid = NULL, *ts = NULL;
    char *extend = NULL;
	int i = 0;

	char* pMacCache = NULL;
	ST_RRE_AUTH* pPreAuthCache = NULL;
	
	static char pMacCache1[16] = {0};
	static ST_RRE_AUTH stPreAuth1 = {0};

	static char pMacCache2[16] = {0};
	static ST_RRE_AUTH stPreAuth2 = {0};
	
    memset(tmp_url, 0, sizeof(tmp_url));
    /* 
     * XXX Note the code below assumes that the client's request is a plain
     * http request to a standard port. At any rate, this handler is called only
     * if the internet/auth server is down so it's not a huge loss, but still.
     */
    snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
	//debug(LOG_INFO, "r->request.query {%s}\n", r->request.query);
    url = httpdUrlEncode(tmp_url);

    if (!is_online()) {
        /* The internet connection is down at the moment  - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that the internet connection that powers this hotspot is temporarily unavailable.</p>"
                      "<p>If at all possible, please notify the owners of this hotspot that the internet connection is out of service.</p>"
                      "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                      "<p>In a while please <a href='%s'>click here</a> to try your request again.</p>", tmp_url);

        send_http_page(r, "Uh oh! Internet access unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server",
              r->clientAddr);
    } else if (!is_auth_online()) {
        /* The auth server is down at the moment - apologize and do not redirect anywhere */
        char *buf;
        safe_asprintf(&buf,
                      "<p>We apologize, but it seems that we are currently unable to re-direct you to the login screen.</p>"
                      "<p>The maintainers of this network are aware of this disruption.  We hope that this situation will be resolved soon.</p>"
                      "<p>In a couple of minutes please <a href='%s'>click here</a> to try your request again.</p>",
                      tmp_url);

        send_http_page(r, "Uh oh! Login screen unavailable!", buf);
        free(buf);
        debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server",
              r->clientAddr);
    } else {
        /* Re-direct them to auth server */
        char *urlFragment;
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_INFO, "Failed to retrieve MAC address for ip %s, so not putting in the login request",
                  r->clientAddr);
            safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&url=%s",
                          auth_server->authserv_login_script_path_fragment, config->gw_address, config->gw_port,
                          config->gw_id, r->clientAddr, url);
        } else
		{	
			safe_asprintf(&urlFragment, "%sgw_address=%s&gw_port=%d&gw_id=%s&ip=%s&mac=%s&url=%s",
                          auth_server->authserv_login_script_path_fragment,
                          config->gw_address, config->gw_port, config->gw_id, r->clientAddr, mac, url);
        }

        // if host is not in whitelist, maybe not in conf or domain'IP changed, it will go to here.
        debug(LOG_INFO, "Check host %s is in whitelist or not", r->request.host);       // e.g. www.example.com
        t_firewall_rule *rule;
        //e.g. example.com is in whitelist
        // if request http://www.example.com/, it's not equal example.com.
        for (rule = get_ruleset("global"); rule != NULL; rule = rule->next) {
            //debug(LOG_INFO, "rule mask %s", rule->mask);
            if (strstr(r->request.host, rule->mask) == NULL) {
               // debug(LOG_INFO, "host %s is not in %s, continue", r->request.host, rule->mask);
                continue;
            }
            int host_length = strlen(r->request.host);
            int mask_length = strlen(rule->mask);
            if (host_length != mask_length) {
                char prefix[1024] = { 0 };
                // must be *.example.com, if not have ".", maybe Phishing. e.g. phishingexample.com
                strncpy(prefix, r->request.host, host_length - mask_length - 1);        // e.g. www
                strcat(prefix, ".");    // www.
                strcat(prefix, rule->mask);     // www.example.com
                if (strcasecmp(r->request.host, prefix) == 0) {
                    debug(LOG_INFO, "allow subdomain");
                    fw_allow_host(r->request.host);
                    http_send_redirect(r, tmp_url, "allow subdomain");
                    free(url);
                    free(urlFragment);
					free(mac);
                    return;
                }
            } else {
                // e.g. "example.com" is in conf, so it had been parse to IP and added into "iptables allow" when wifidog start. but then its' A record(IP) changed, it will go to here.
                debug(LOG_INFO, "allow domain again, because IP changed");
                fw_allow_host(r->request.host);
                http_send_redirect(r, tmp_url, "allow domain");
                free(url);
                free(urlFragment);
				free(mac);
                return;
            }
        }
		
		if(mac == NULL)
		{
			debug(LOG_INFO, "1->http_callback_404():Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
	        http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
		}
		else
		{
			if((pPreAuthClientCache == NULL) || (strncmp(pPreAuthClientCache->mac,mac,strlen(mac))))
			{
				LOCK_CLIENT_LIST();
				if((pPreAuthClientCache == NULL) || (strncmp(pPreAuthClientCache->mac,mac,strlen(mac))))
				{
					if ((pPreAuthClientCache = find_in_pre_auth_list(mac)) == NULL) 
					{
		            	debug(LOG_INFO, "http_callback_404():New client for %s", r->clientAddr);

						CalMd5(mac,md5);
						UnzipStr(token_md5, md5, 32);	

						insert_in_in_pre_auth_list(mac,r->clientAddr,token_md5);
		          	
						debug(LOG_INFO, "[CIG] auth_server_request: r->clientAddr[%s] before\n",r->clientAddr);
						auth_server_request(&auth_response, REQUEST_TYPE_PREAUTH, r->clientAddr, mac, token_md5, 0, 0, 0, 0);
						debug(LOG_INFO, "[CIG]auth_server_request: r->clientAddr[%s] result is %d\n",r->clientAddr,auth_response.authcode);

						if(auth_response.authcode == AUTH_ALLOWED)
						{
				            debug(LOG_INFO, "http_callback_404():Got ALLOWED from central server authenticating token %s from %s at %s - "
				                    "adding to firewall and redirecting them to portal", token_md5,r->clientAddr, mac);
							if ((client = client_list_find(r->clientAddr, mac)) == NULL) 
							{
								client_list_add(r->clientAddr, mac, token_md5);
								client = client_list_find(r->clientAddr, mac);
								fw_allow(client, FW_MARK_KNOWN);
				           		served_this_session++;
							}

							http_send_redirect(r, url, "Redirect to user access page");

						}
						else
						{
							debug(LOG_INFO, "2->http_callback_404():Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
				        	http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
						}
					}			

				}
				
				UNLOCK_CLIENT_LIST();

			}
			else
			{
				debug(LOG_INFO, "3->http_callback_404():Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
	        	http_send_redirect_to_auth(r, urlFragment, "Redirect to login page");
			}
				
		}

		free(mac);
		free(urlFragment);
    }
    free(url);
	
}

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void
http_callback_status(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    char *status = NULL;
    char *buf;

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Status page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "WiFiDog Status", buf);
    free(buf);
    free(status);
}

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
{
    char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }

    char *url = NULL;
    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path, urlFragment);
    http_send_redirect(r, url, text);
    free(url);
}

/** @brief Sends a redirect to the web browser 
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void
http_send_redirect(request * r, const char *url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
    safe_asprintf(&response, "302 %s\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);
    safe_asprintf(&message, "Please <a href='%s'>click here</a>.", url);
    send_http_page(r, text ? text : "Redirection to message", message);
    free(message);
}

void
http_callback_auth(httpd * webserver, request * r)
{
    t_client *client;
    httpVar *token;
    char *mac;
    httpVar *logout = httpdGetVariableByName(r, "logout");

    if ((token = httpdGetVariableByName(r, "token"))) {
        /* They supplied variable "token" */
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();

            if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
                debug(LOG_DEBUG, "New client for %s", r->clientAddr);
                client_list_add(r->clientAddr, mac, token->value);
            } else if (logout) {
                logout_client(client);
            } else {
                debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
            }

            UNLOCK_CLIENT_LIST();
            if (!logout) { /* applies for case 1 and 3 from above if */
                authenticate_client(r);
            }
            free(mac);
        }
    } else {
        /* They did not supply variable "token" */
        send_http_page(r, "WiFiDog error", "Invalid token");
    }
}

void
http_callback_disconnect(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    /* XXX How do you change the status code for the response?? */
    httpVar *token = httpdGetVariableByName(r, "token");
    httpVar *mac = httpdGetVariableByName(r, "mac");

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    if (token && mac) {
        t_client *client;

        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac->value);

        if (!client || strcmp(client->token, token->value)) {
            UNLOCK_CLIENT_LIST();
            debug(LOG_INFO, "Disconnect %s with incorrect token %s", mac->value, token->value);
            httpdOutput(r, "Invalid token for MAC");
            return;
        }

        /* TODO: get current firewall counters */
        logout_client(client);
        UNLOCK_CLIENT_LIST();

    } else {
        debug(LOG_INFO, "Disconnect called without both token and MAC given");
        httpdOutput(r, "Both the token and MAC need to be specified");
        return;
    }

    return;
}

void
send_http_page(request * r, const char *title, const char *message)
{
    s_config *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}
