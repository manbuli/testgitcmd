/* vim: set et ts=4 sts=4 sw=4 : */
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
/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

#include "portRange.h"

static int iptables_do_command(const char *format, ...);
static char *iptables_compile(const char *, const char *, const t_firewall_rule *);
static void iptables_load_ruleset(const char *, const char *, const char *);

/**
Used to supress the error output of the firewall during destruction */
static int fw_quiet = 0;

/** @internal
 * @brief Insert $ID$ with the gateway's id in a string.
 *
 * This function can replace the input string with a new one. It assumes
 * the input string is dynamically allocted and can be free()ed safely.
 *
 * This function must be called with the CONFIG_LOCK held.
 */
static void
iptables_insert_gateway_id(char **input)
{
    char *token;
    const s_config *config;
    char *buffer;

    if (strstr(*input, "$ID$") == NULL)
        return;

    while ((token = strstr(*input, "$ID$")) != NULL)
        /* This string may look odd but it's standard POSIX and ISO C */
        memcpy(token, "%1$s", 4);

    config = config_get_config();
    safe_asprintf(&buffer, *input, config->gw_interface);

    free(*input);
    *input = buffer;
}

/** @internal 
 * */
static int
iptables_do_command(const char *format, ...)
{
    va_list vlist;
    char *fmt_cmd;
    char *cmd;
    int rc;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
    free(fmt_cmd);

    iptables_insert_gateway_id(&cmd);

    debug(LOG_DEBUG, "Executing command: %s", cmd);

    rc = execute(cmd, fw_quiet);

    if (rc != 0) {
        // If quiet, do not display the error
        if (fw_quiet == 0)
            debug(LOG_ERR, "iptables command failed(%d): %s", rc, cmd);
        else if (fw_quiet == 1)
            debug(LOG_DEBUG, "iptables command failed(%d): %s", rc, cmd);
    }

    free(cmd);

    return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg table Table containing the chain.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
static char *
iptables_compile(const char *table, const char *chain, const t_firewall_rule * rule)
{
    char command[MAX_BUF], *mode;

    memset(command, 0, MAX_BUF);
    mode = NULL;

    switch (rule->target) {
    case TARGET_DROP:
        if (strncmp(table, "nat", 3) == 0) {
            free(mode);
            return NULL;
        }
        mode = safe_strdup("DROP");
        break;
    case TARGET_REJECT:
        if (strncmp(table, "nat", 3) == 0) {
            free(mode);
            return NULL;
        }
        mode = safe_strdup("REJECT");
        break;
    case TARGET_ACCEPT:
        mode = safe_strdup("ACCEPT");
        break;
    case TARGET_LOG:
        mode = safe_strdup("LOG");
        break;
    case TARGET_ULOG:
        mode = safe_strdup("ULOG");
        break;
    }

    snprintf(command, sizeof(command), "-t %s -A %s ", table, chain);
    if (rule->mask != NULL) {
        if (rule->mask_is_ipset) {
            snprintf((command + strlen(command)), (sizeof(command) -
                                                   strlen(command)), "-m set --match-set %s dst ", rule->mask);
        } else {
            snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-d %s ", rule->mask);
        }
    }
    if (rule->protocol != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-p %s ", rule->protocol);
    }
    if (rule->port != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "--dport %s ", rule->port);
    }
    snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-j %s", mode);

    free(mode);

    /* XXX The buffer command, an automatic variable, will get cleaned
     * off of the stack when we return, so we strdup() it. */
    return (safe_strdup(command));
}

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
static void
iptables_load_ruleset(const char *table, const char *ruleset, const char *chain)
{
    t_firewall_rule *rule;
    char *cmd;

    debug(LOG_DEBUG, "Load ruleset %s into table %s, chain %s", ruleset, table, chain);

    for (rule = get_ruleset(ruleset); rule != NULL; rule = rule->next) {
        cmd = iptables_compile(table, chain, rule);
        if (cmd != NULL) {
            debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
            iptables_do_command(cmd);
        }
        free(cmd);
    }

    debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
}

void
iptables_fw_clear_authservers(void)
{
    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
}

void
iptables_fw_set_authservers(void)
{
    const s_config *config;
    t_auth_serv *auth_server;

    config = config_get_config();

    for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
        if (auth_server->last_ip && strcmp(auth_server->last_ip, "0.0.0.0") != 0) {
            iptables_do_command("-t filter -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip); 
			iptables_do_command("-t filter -I " CHAIN_AUTHSERVERS " -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --set-mss %d", 1412);
            iptables_do_command("-t nat -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
        }
    }

}

/** Initialize the firewall rules
*/
int
iptables_fw_init(void)
{
    s_config *config;
    char *ext_interface = NULL;
    int gw_port = 0;
    t_trusted_mac *p;
    int proxy_port;
    fw_quiet = 0;
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;

    LOCK_CONFIG();
    config = config_get_config();
    gw_port = config->gw_port;
    if (config->external_interface) {
        ext_interface = safe_strdup(config->external_interface);
    } else {
        ext_interface = get_ext_iface();
    }

    if (ext_interface == NULL) {
        UNLOCK_CONFIG();
        debug(LOG_ERR, "FATAL: no external interface");
        return 0;
    } 
    
//#ifdef PORT_RANGE
    if ( !config->external_interface ) {
        config->external_interface = strdup(ext_interface);
    }
    
    /* If we don't have the Gateway IP address, get it. Can't fail. */
    debug(LOG_DEBUG, "Finding IP address of %s", config->external_interface);
    //if ((config->external_ip= get_iface_ip(config->external_interface)) == NULL) {
	if ((config->external_ip= get_iface_ip_ex(config->external_interface)) == NULL) {
        debug(LOG_ERR, "Could not get IP address information of %s, exiting...", config->external_interface);
        exit(1);
    }
    debug(LOG_DEBUG, "%s = %s", config->external_interface, config->external_ip);
//#endif
 
    /*
     *
     * Everything in the MANGLE table
     *
     */

    /* Create new chains */
    iptables_do_command("-t mangle -N " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -N " CHAIN_OUTGOING);
    iptables_do_command("-t mangle -N " CHAIN_INCOMING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_OUTGOING, config->gw_interface);
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_TRUSTED, config->gw_interface);     //this rule will be inserted before the prior one
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_AUTH_IS_DOWN, config->gw_interface);    //this rule must be last in the chain
    iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -j " CHAIN_INCOMING, config->gw_interface);

    for (p = config->trustedmaclist; p != NULL; p = p->next)
        iptables_do_command("-t mangle -A " CHAIN_TRUSTED " -m mac --mac-source %s -j MARK --set-mark %d", p->mac,
                            FW_MARK_KNOWN);

    /*
     *
     * Everything in the NAT table
     *
     */

    /* Create new chains */
    iptables_do_command("-t nat -N " CHAIN_OUTGOING);
    iptables_do_command("-t nat -N " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -N " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -N " CHAIN_GLOBAL);
    iptables_do_command("-t nat -N " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -N " CHAIN_AUTHSERVERS);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
//    iptables_do_command("-t nat -A PREROUTING -i %s -j " CHAIN_OUTGOING, config->gw_interface);
    iptables_do_command("-t nat -A PREROUTING -i %s -m mark --mark %d -j " CHAIN_OUTGOING, config->gw_interface, FW_MARK_WHITE_LIST);

    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -d %s -j " CHAIN_TO_ROUTER, config->gw_address);
    iptables_do_command("-t nat -A " CHAIN_TO_ROUTER " -j ACCEPT");

    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j " CHAIN_TO_INTERNET);

    if ((proxy_port = config_get_config()->proxy_port) != 0) {
        debug(LOG_DEBUG, "Proxy port set, setting proxy rule");
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET
                            " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_KNOWN,
                            proxy_port);
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET
                            " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_PROBATION,
                            proxy_port);
    }

    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_KNOWN);
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_PROBATION);
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);

    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_GLOBAL);
    if (got_authdown_ruleset) {
        iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTH_IS_DOWN);
        iptables_do_command("-t nat -A " CHAIN_AUTH_IS_DOWN " -m mark --mark 0x%u -j ACCEPT", FW_MARK_AUTH_IS_DOWN);
    }
    //iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port);
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -p tcp --dport 80  -j DNAT --to-destination %s:%d",  config->gw_address, gw_port);

    /*
     *
     * Everything in the FILTER table
     *
     */

    /* Create new chains */
    iptables_do_command("-t filter -N " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -N " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -N " CHAIN_LOCKED);
    iptables_do_command("-t filter -N " CHAIN_GLOBAL);
    iptables_do_command("-t filter -N " CHAIN_VALIDATE);
    iptables_do_command("-t filter -N " CHAIN_KNOWN);
    iptables_do_command("-t filter -N " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */

    /* Insert at the beginning */
    //iptables_do_command("-t filter -I FORWARD -i %s -j " CHAIN_TO_INTERNET, config->gw_interface);
    iptables_do_command("-t filter -I FORWARD -i %s -m mark --mark %d -j " CHAIN_TO_INTERNET, config->gw_interface, FW_MARK_WHITE_LIST);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state INVALID -j DROP");

    /* XXX: Why this? it means that connections setup after authentication
       stay open even after the connection is done... 
       iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state RELATED,ESTABLISHED -j ACCEPT"); */

    //Won't this rule NEVER match anyway?!?!? benoitg, 2007-06-23
    //iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -i %s -m state --state NEW -j DROP", ext_interface);

    /* TCPMSS rule for PPPoE */
    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET
                        " -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ext_interface);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_AUTHSERVERS);
    iptables_fw_set_authservers();

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_LOCKED, FW_MARK_LOCKED);
    iptables_load_ruleset("filter", FWRULESET_LOCKED_USERS, CHAIN_LOCKED);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_GLOBAL);
    iptables_load_ruleset("filter", FWRULESET_GLOBAL, CHAIN_GLOBAL);
    iptables_load_ruleset("nat", FWRULESET_GLOBAL, CHAIN_GLOBAL);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_VALIDATE, FW_MARK_PROBATION);
    iptables_load_ruleset("filter", FWRULESET_VALIDATING_USERS, CHAIN_VALIDATE);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_KNOWN, FW_MARK_KNOWN);
    iptables_load_ruleset("filter", FWRULESET_KNOWN_USERS, CHAIN_KNOWN);

    if (got_authdown_ruleset) {
        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_AUTH_IS_DOWN,
                            FW_MARK_AUTH_IS_DOWN);
        iptables_load_ruleset("filter", FWRULESET_AUTH_IS_DOWN, CHAIN_AUTH_IS_DOWN);
    }

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);
    iptables_load_ruleset("filter", FWRULESET_UNKNOWN_USERS, CHAIN_UNKNOWN);
    //iptables_do_command("-t filter -A " CHAIN_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");
    iptables_do_command("-t filter -A " CHAIN_UNKNOWN " -j REJECT ");

    UNLOCK_CONFIG();

    free(ext_interface);
    return 1;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
int
iptables_fw_destroy(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    fw_quiet = 1;

    debug(LOG_DEBUG, "Destroying our iptables entries");

    /*
     *
     * Everything in the MANGLE table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_TRUSTED);
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_AUTH_IS_DOWN);
    iptables_fw_destroy_mention("mangle", "POSTROUTING", CHAIN_INCOMING);
    iptables_do_command("-t mangle -F " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t mangle -F " CHAIN_INCOMING);
    iptables_do_command("-t mangle -X " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t mangle -X " CHAIN_INCOMING);

    /*
     *
     * Everything in the NAT table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the NAT table");
    iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -F " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -F " CHAIN_GLOBAL);
    iptables_do_command("-t nat -F " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -X " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -X " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -X " CHAIN_GLOBAL);
    iptables_do_command("-t nat -X " CHAIN_UNKNOWN);

    /*
     *
     * Everything in the FILTER table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the FILTER table");
    iptables_fw_destroy_mention("filter", "FORWARD", CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -F " CHAIN_LOCKED);
    iptables_do_command("-t filter -F " CHAIN_GLOBAL);
    iptables_do_command("-t filter -F " CHAIN_VALIDATE);
    iptables_do_command("-t filter -F " CHAIN_KNOWN);
    iptables_do_command("-t filter -F " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t filter -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -X " CHAIN_AUTHSERVERS);
    iptables_do_command("-t filter -X " CHAIN_LOCKED);
    iptables_do_command("-t filter -X " CHAIN_GLOBAL);
    iptables_do_command("-t filter -X " CHAIN_VALIDATE);
    iptables_do_command("-t filter -X " CHAIN_KNOWN);
    iptables_do_command("-t filter -X " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -X " CHAIN_AUTH_IS_DOWN);

    return 1;
}

/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
int
iptables_fw_destroy_mention(const char *table, const char *chain, const char *mention)
{
    FILE *p = NULL;
    char *command = NULL;
    char *command2 = NULL;
    char line[MAX_BUF];
    char rulenum[10];
    char *victim = safe_strdup(mention);
    int deleted = 0;

    iptables_insert_gateway_id(&victim);

    debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", victim, table, chain);

    safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
    iptables_insert_gateway_id(&command);

    if ((p = popen(command, "r"))) {
        /* Skip first 2 lines */
        while (!feof(p) && fgetc(p) != '\n') ;
        while (!feof(p) && fgetc(p) != '\n') ;
        /* Loop over entries */
        while (fgets(line, sizeof(line), p)) {
            /* Look for victim */
            if (strstr(line, victim)) {
                /* Found victim - Get the rule number into rulenum */
                if (sscanf(line, "%9[0-9]", rulenum) == 1) {
                    /* Delete the rule: */
                    debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain,
                          victim);
                    safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
                    iptables_do_command(command2);
                    free(command2);
                    deleted = 1;
                    /* Do not keep looping - the captured rulenums will no longer be accurate */
                    break;
                }
            }
        }
        pclose(p);
    }

    free(command);
    free(victim);

    if (deleted) {
        /* Recurse just in case there are more in the same table+chain */
        iptables_fw_destroy_mention(table, chain, mention);
    }

    return (deleted);
}

//#ifdef PORT_RANGE
int send_to_wifiaudit(char *sndbuf, int sndlen)
{
    int slen, socket_descriptor; //套接口描述字
    struct sockaddr_in address;//处理网络通信的地址

    bzero(&address,sizeof(address));
    address.sin_family=AF_INET;
    address.sin_addr.s_addr=inet_addr("127.0.0.1");//这里不一样
    address.sin_port=htons(8000);

    //创建一个 UDP socket
    socket_descriptor=socket(AF_INET,SOCK_DGRAM,0);

      
    /*int PASCAL FAR sendto( SOCKET s, const char FAR* buf, int len, int flags,const struct sockaddr FAR* to, int tolen);　　
    * s：一个标识套接口的描述字。　
    * buf：包含待发送数据的缓冲区。　　
    * len：buf缓冲区中数据的长度。　
    * flags：调用方式标志位。　　
    * to：（可选）指针，指向目的套接口的地址。　
    * tolen：to所指地址的长度。  
    */
    slen = sendto(socket_descriptor,sndbuf,sndlen,0,(struct sockaddr *)&address,sizeof(address));
    close(socket_descriptor);

		return slen == sndlen;
}

/* utility function to convert hex character representation to their nibble (4 bit) values */
static u_char nibbleFromChar(char c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
		return 255;
}

int convertMacStringToMacHex(const char *strMac, u_char macHex[])
{
	int i = 0;
	const char *pv = strMac;

	// MAC地址格式：D8-D3-85-2A-B0-76
	if ( !strMac )
		return 0;

	i = 0;
	do 
	{
		if ( *pv == 0 || i == 6 )
		{
			break;
		}
		macHex[i++] = (nibbleFromChar(*pv) << 4) | nibbleFromChar(*(pv+1));
		pv += 3;

	} while ( 1 );

	return 1;
}


//#endif

/** Set if a specific client has access through the firewall */
int
iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    int rc;

//#ifdef PORT_RANGE
    uint16 lport, hport;
    int rt;
    const s_config *config;
    char sndbuf[64];
	u_char macHex[6];
    int sndlen;
//#endif

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        iptables_do_command("-t mangle -A " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip,
                            mac, tag);
        rc = iptables_do_command("-t mangle -A " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
//#ifdef PORT_RANGE
        config = config_get_config();
        convertMacStringToMacHex(mac, macHex);
       rt = getPortRange(macHex, &lport, &hport); 
       if ( rt == 1 )
       {
           iptables_do_command("-t nat -D POSTROUTING -s %s -p tcp -o %s -j SNAT --to %s:%d-%d",
                   ip, config->external_interface, config->external_ip, lport, hport - 200 );
           iptables_do_command("-t nat -D POSTROUTING -s %s -p udp -o %s -j SNAT --to %s:%d-%d",
                   ip, config->external_interface, config->external_ip, hport - 200 + 1, hport);

           iptables_do_command("-t nat -I POSTROUTING -s %s -p tcp -o %s -j SNAT --to %s:%d-%d",
                   ip, config->external_interface, config->external_ip, lport, hport - 200 );
           iptables_do_command("-t nat -I POSTROUTING -s %s -p udp -o %s -j SNAT --to %s:%d-%d",
                   ip, config->external_interface, config->external_ip, hport - 200 + 1, hport);

           sndlen = snprintf(sndbuf, sizeof(sndbuf), "100#%s#%d#%d",
                   mac, lport, hport);

           //debug(LOG_INFO, "send buf to audit, %s", sndbuf);
           //send_to_wifiaudit(sndbuf, sndlen);
       }
       else
       {
            debug(LOG_WARNING, "can't alloc port by mac:%s", mac);
       }
//#endif
        break;
    case FW_ACCESS_DENY:
        /* XXX Add looping to really clear? */
        iptables_do_command("-t mangle -D " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip,
                            mac, tag);
        rc = iptables_do_command("-t mangle -D " CHAIN_INCOMING " -d %s -j ACCEPT", ip);

//#ifdef PORT_RANGE
        config = config_get_config();
        convertMacStringToMacHex(mac, macHex);
       rt = queryPortRangeByMacAddress(macHex, &lport, &hport); 
       
       if ( rt == 1 )
       {
           iptables_do_command("-t nat -D POSTROUTING -s %s -p tcp -o %s -j SNAT --to %s:%d-%d",
                   ip, config->external_interface, config->external_ip, lport, hport - 200 );
           iptables_do_command("-t nat -D POSTROUTING -s %s -p udp -o %s -j SNAT --to %s:%d-%d",
                   ip, config->external_interface, config->external_ip, hport - 200 + 1, hport);

           sndlen = snprintf(sndbuf, sizeof(sndbuf), "101#%s",
                   mac);

           //debug(LOG_INFO, "send buf to audit, %s", sndbuf);
           //send_to_wifiaudit(sndbuf, sndlen);

           updatePortRange(macHex);
       }
       else
       {
           debug(LOG_WARNING, "can't find the lport and hport by mac: %s", mac);
       } 
//#endif
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

int
iptables_fw_access_host(fw_access_t type, const char *host)
{
    int rc;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        iptables_do_command("-t nat -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        rc = iptables_do_command("-t filter -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    case FW_ACCESS_DENY:
        iptables_do_command("-t nat -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        rc = iptables_do_command("-t filter -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

/** Set a mark when auth server is not reachable */
int
iptables_fw_auth_unreachable(int tag)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    if (got_authdown_ruleset)
        return iptables_do_command("-t mangle -A " CHAIN_AUTH_IS_DOWN " -j MARK --set-mark 0x%u", tag);
    else
        return 1;
}

/** Remove mark when auth server is reachable again */
int
iptables_fw_auth_reachable(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    if (got_authdown_ruleset)
        return iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN);
    else
        return 1;
}

/** Update the counters of all the clients in the client list */
int
iptables_fw_counters_update(void)
{
    FILE *output;
    char *script, ip[16], rc;
    unsigned long long int counter;
    t_client *p1;
    struct in_addr tempaddr;

    /* Look for outgoing traffic */
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_OUTGOING);
    iptables_insert_gateway_id(&script);
    output = popen(script, "r");
    free(script);
    if (!output) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s %*s", &counter, ip);
        //rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s 0x%*u", &counter, ip);
        if (2 == rc && EOF != rc) {
            /* Sanity */
            if (!inet_aton(ip, &tempaddr)) {
                debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
                continue;
            }
            debug(LOG_DEBUG, "Read outgoing traffic for %s: Bytes=%llu", ip, counter);
            LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if ((p1->counters.outgoing - p1->counters.outgoing_history) < counter) {
                    p1->counters.outgoing_delta = p1->counters.outgoing_history + counter - p1->counters.outgoing;
                    p1->counters.outgoing = p1->counters.outgoing_history + counter;
                    p1->counters.last_updated = time(NULL);
                    debug(LOG_DEBUG, "%s - Outgoing traffic %llu bytes, updated counter.outgoing to %llu bytes.  Updated last_updated to %d", ip,
                          counter, p1->counters.outgoing, p1->counters.last_updated);
                }
            } else {
                debug(LOG_ERR,
                      "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed",
                      ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_OUTGOING);
                iptables_fw_destroy_mention("mangle", CHAIN_OUTGOING, ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_INCOMING);
                iptables_fw_destroy_mention("mangle", CHAIN_INCOMING, ip);
            }
            UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);

    /* Look for incoming traffic */
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_INCOMING);
    iptables_insert_gateway_id(&script);
    output = popen(script, "r");
    free(script);
    if (!output) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %*s %15[0-9.]", &counter, ip);
        if (2 == rc && EOF != rc) {
            /* Sanity */
            if (!inet_aton(ip, &tempaddr)) {
                debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
                continue;
            }
            debug(LOG_DEBUG, "Read incoming traffic for %s: Bytes=%llu", ip, counter);
            LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if ((p1->counters.incoming - p1->counters.incoming_history) < counter) {
                    p1->counters.incoming_delta = p1->counters.incoming_history + counter - p1->counters.incoming;
                    p1->counters.incoming = p1->counters.incoming_history + counter;
                    debug(LOG_DEBUG, "%s - Incoming traffic %llu bytes, Updated counter.incoming to %llu bytes", ip, counter, p1->counters.incoming);
                }
            } else {
                debug(LOG_ERR,
                      "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed",
                      ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_OUTGOING);
                iptables_fw_destroy_mention("mangle", CHAIN_OUTGOING, ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_INCOMING);
                iptables_fw_destroy_mention("mangle", CHAIN_INCOMING, ip);
            }
            UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);

    return 1;
}
