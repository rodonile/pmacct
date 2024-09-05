/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include "pmacct.h"
#include "bgp/bgp.h"
#include "bmp.h"

void bmp_srcdst_lookup(struct packet_ptrs *pptrs, struct bgp_lookup_info *bl_info)
{
  bgp_srcdst_lookup(pptrs, FUNC_TYPE_BMP, bl_info);
}

// This is how we find the BMP parent peer (then the modulo function will take care of finding the info...)
struct bgp_peer *bgp_lookup_find_bmp_peer(struct sockaddr *sa, struct xflow_status_entry *xs_entry, u_int16_t l3_proto, int compare_bgp_port)
{
  struct bgp_peer *peer;
  u_int32_t peer_idx, *peer_idx_ptr;
  int peers_idx;

  peer_idx = 0; peer_idx_ptr = NULL;
  if (xs_entry) {
    if (l3_proto == ETHERTYPE_IP) {
      peer_idx = xs_entry->peer_v4_idx;
      peer_idx_ptr = &xs_entry->peer_v4_idx;
    }
    else if (l3_proto == ETHERTYPE_IPV6) {
      peer_idx = xs_entry->peer_v6_idx;
      peer_idx_ptr = &xs_entry->peer_v6_idx;
    }
  }

  if (xs_entry && peer_idx) {
    Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: matching in xs_entry, peer_idx=%d\n", config.name, peer_idx);
    if (!sa_addr_cmp(sa, &bmp_peers[peer_idx].self.addr) || !sa_addr_cmp(sa, &bmp_peers[peer_idx].self.id))
      peer = &bmp_peers[peer_idx].self;
    /* If no match then let's invalidate the entry */
    else {
      *peer_idx_ptr = 0;
      peer = NULL;
    }
  }
  else {
    /* use-case #1: BMP peer being the edge router */
    int bmp_peer_found = FALSE;
    for (peer = NULL, peers_idx = 0; peers_idx < config.bmp_daemon_max_peers; peers_idx++) {
      Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer[case1]: iter peer_idx=%d\n", config.name, peers_idx);
      
      if (!sa_addr_cmp(sa, &bmp_peers[peers_idx].self.addr) || !sa_addr_cmp(sa, &bmp_peers[peers_idx].self.id)) {
        peer = &bmp_peers[peers_idx].self;
        if (xs_entry && peer_idx_ptr) *peer_idx_ptr = peers_idx;

        /* TEMP DBG LOG*/
        Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: found the BMP parent peer\n", config.name);
        char bmp_peer_addr[INET6_ADDRSTRLEN];
        memset(bmp_peer_addr, 0, INET6_ADDRSTRLEN);
        addr_to_str2(bmp_peer_addr, &bmp_peers[peers_idx].self.addr, AF_INET6);  
        Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: BMP Peer Addr =  %s\n", config.name, bmp_peer_addr);
        char bgp_id_str[INET6_ADDRSTRLEN];
        memset(bgp_id_str, 0, INET6_ADDRSTRLEN);
        addr_to_str2(bgp_id_str, &bmp_peers[peers_idx].self.id, AF_INET);  
        Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: BMP Peer ID =  %s\n", config.name, bgp_id_str);
        /* TEMP DBG LOG*/

        bmp_peer_found = TRUE;
        break;
      }
    }

    /* use-case #2: BMP peer being the reflector; XXX: fix caching */
    if (!bmp_peer_found) {
      for (peer = NULL, peers_idx = 0; peers_idx < config.bmp_daemon_max_peers; peers_idx++) {
        Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer[case2]: iter peer_idx=%d\n", config.name, peers_idx);
        void *ret = NULL;

        // TODO: here understand and see if we also need to change to find the correct peer? -> no because it's global instance 
        //       so it just matters to find the peer
        //       --> however there's a problem, we will not be able to correlate since we'll end up in a bucket according to the flow RD 
        if (sa->sa_family == AF_INET) {
          ret = pm_tfind(sa, &bmp_peers[peers_idx].bgp_peers_v4, bgp_peer_sa_addr_cmp);

          //TEMP DEBUG:
          // Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: found the BGP v4 child peer\n", config.name);
        }
        else if (sa->sa_family == AF_INET6) {
          ret = pm_tfind(sa, &bmp_peers[peers_idx].bgp_peers_v6, bgp_peer_sa_addr_cmp);

          //TEMP DEBUG:
          // Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: found the BGP v6 child peer\n", config.name);
        }

        if (ret) {
          peer = (*(struct bgp_peer **) ret);

          /* TEMP DBG LOG*/
          struct bmp_peer *bmpp = peer->bmp_se;

          Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: found the BGP child peer\n", config.name);
          char bgp_peer_addr[INET6_ADDRSTRLEN];
          memset(bgp_peer_addr, 0, INET6_ADDRSTRLEN);
          addr_to_str2(bgp_peer_addr, &peer->addr, AF_INET6);  
          Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: BGP Peer Addr =  %s\n", config.name, bgp_peer_addr);
          char bgp_id_str[INET6_ADDRSTRLEN];
          memset(bgp_id_str, 0, INET6_ADDRSTRLEN);
          addr_to_str2(bgp_id_str, &peer->id, AF_INET);  
          Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: BGP Peer ID =  %s\n", config.name, bgp_id_str);
          char bmp_peer_addr[INET6_ADDRSTRLEN];
          memset(bmp_peer_addr, 0, INET6_ADDRSTRLEN);
          addr_to_str2(bmp_peer_addr, &bmpp->self.addr, AF_INET6);  
          Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: BMP Parent Peer Addr =  %s\n", config.name, bmp_peer_addr);
          char bmp_id_str[INET6_ADDRSTRLEN];
          memset(bmp_id_str, 0, INET6_ADDRSTRLEN);
          addr_to_str2(bmp_id_str, &bmpp->self.id, AF_INET);  
          Log(LOG_INFO, "INFO ( %s/config/BMP ): bgp_lookup_find_bmp_peer: BMP Parent Peer ID =  %s\n", config.name, bmp_id_str);
          /* TEMP DBG LOG*/

          break;
        }
      }
    }
  }

  return peer;
}

u_int32_t bmp_route_info_modulo_pathid(struct bgp_peer *peer, rd_t *rd, path_id_t *path_id, struct bgp_msg_extra_data *bmed, int per_peer_buckets)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);
  struct bmp_peer *bmpp = peer->bmp_se;
  path_id_t local_path_id = 1;
  int fd = 0;

  if (path_id && *path_id) local_path_id = *path_id;

  if (peer->fd) {
    fd = peer->fd;
    // Log(LOG_INFO, "INFO ( %s/config/BMP ): bmp_route_info_modulo_pathid: fd=%d\n", config.name, fd);
  }
  else {
    if (bmpp && bmpp->self.fd) { 
      fd = bmpp->self.fd;
      // Log(LOG_INFO, "INFO ( %s/config/BMP ): bmp_route_info_modulo_pathid: using the parent BMP peer fd (=%d) for child BGP Peer\n", config.name, fd);
    }
  }

  return (((fd * per_peer_buckets) +
          ((local_path_id - 1) % per_peer_buckets)) %
          (bms->table_peer_buckets * per_peer_buckets));
}

u_int32_t bmp_route_info_modulo_mplsvpnrd(struct bgp_peer *peer, rd_t *rd, path_id_t *path_id, struct bgp_msg_extra_data *bmed, int per_peer_buckets)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);
  struct bmp_peer *bmpp = peer->bmp_se;
  u_int16_t local_rd = 0;
  int fd = 0;

  if (bmed) { /* BMP message being parsed (RD is stored in bmed->data->rd) */
    struct bmp_chars *bmed_bmp_chars = (struct bmp_chars *) bmed->data;
    if (bmed_bmp_chars->rd.val) local_rd = (bmed_bmp_chars->rd.type + bmed_bmp_chars->rd.as + bmed_bmp_chars->rd.val);
  }
  else { /* Correlating with flow */
    if (rd) local_rd = (rd->type + rd->as + rd->val);
  }

  if (peer->fd) {
    fd = peer->fd;
    // Log(LOG_INFO, "INFO ( %s/config/BMP ): bmp_route_info_modulo_mplsvpnrd: fd=%d\n", config.name, fd);
  }
  else {
    if (bmpp && bmpp->self.fd) { 
      fd = bmpp->self.fd;
      // Log(LOG_INFO, "INFO ( %s/config/BMP ): bmp_route_info_modulo_mplsvpnrd: using the parent BMP peer fd (=%d) for child BGP Peer\n", config.name, fd);
    }
  }

  return (((fd * per_peer_buckets) +
          (local_rd % per_peer_buckets)) %
          (bms->table_peer_buckets * per_peer_buckets));
}

// Function to print memory in hex
void print_hex(const void *ptr, size_t size) {
    const uint8_t *byte_ptr = (const uint8_t *)ptr;
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", byte_ptr[i]);
    }
    printf("\n");
}

int bgp_lookup_node_match_cmp_bmp(struct bgp_info *info, struct node_match_cmp_term2 *nmct2)
{
  struct bmp_peer *bmpp = info->peer->bmp_se;
  struct bgp_peer *peer_local = &bmpp->self; //BMP peer
  struct bgp_peer *peer_remote = info->peer;  //BGP peer
  int no_match = FALSE, compare_rd = FALSE;

  /* peer_local: edge router use-case; peer_remote: replicator use-case */
  if (peer_local == nmct2->peer || peer_remote == nmct2->peer) { //nmct2->peer is set with the bgp_lookup_find_bmp_peer function above!
    if (nmct2->safi == SAFI_MPLS_VPN || !is_empty_256b(nmct2->rd, sizeof(rd_t))) {
      no_match++;
      compare_rd = TRUE;
      Log(LOG_INFO, "INFO ( %s/config/BMP ): setting compare_rd=TRUE!\n", config.name);

    }

    if (nmct2->peer->cap_add_paths.cap[nmct2->afi][nmct2->safi]) no_match++;

    if (compare_rd) {

      char rd_str[SHORTSHORTBUFLEN];
      bgp_rd2str(rd_str, nmct2->rd);
      Log(LOG_INFO, "INFO ( %s/config/BMP ): RD from IPFIX = %s\n", config.name, rd_str);
      char rd_str_2[SHORTSHORTBUFLEN];
      if (info->attr_extra) bgp_rd2str(rd_str_2, &info->attr_extra->rd);
      else if (info->bmed.id == BGP_MSG_EXTRA_DATA_BMP) {
	struct bmp_chars *bmed_bmp = (struct bmp_chars *) info->bmed.data;
        bgp_rd2str(rd_str_2, &bmed_bmp->rd);
      }
      else strcpy(rd_str_2, "NO RD FOUND");
      Log(LOG_INFO, "INFO ( %s/config/BMP ): RD from BGP = %s\n", config.name, rd_str_2);

      // // Print the actual hex values in memory
      // printf("Hex dump of nmct2->rd:\n");
      // print_hex(nmct2->rd, sizeof(rd_t));

      // printf("Hex dump of &info->attr_extra->rd:\n");
      // print_hex(&info->attr_extra->rd, sizeof(rd_t));  

      /* RD typical location (i.e. BGP vpnv4/6 extention) */  
      // TODO: this would not work with rd in modulo function (as the modulo will send us directly to the bucket with matching PD from loc-rib) --> fix/need???
      // TODO: discuss about prioritization of RiBs (I would say loc-rib>adj-rib-in>adj-rib-out, but how to implement this here???)

      // if (info->attr_extra && !memcmp(&info->attr_extra->rd, nmct2->rd, sizeof(rd_t))) {
      if (info->attr_extra) {
        // TODO: THE FOLLOWING IS NEEDED S.T. THE COMPARISON OF RD WITH RD_ORIGIN BGP (VPNV4 BGP MESSAGES) TO WORK
        // However if we enable it then if we end up in the same per_peer bucket with 0:0 when calculating modulo for ipfix RD, then we might correlate
        //     with information from Adj-RIB-In if we find it before loc-rib... --> this is not good.
        rd_t rd1;
        rd_t rd2;
        memcpy(&rd1, nmct2->rd, sizeof(rd_t));
        memcpy(&rd2, &info->attr_extra->rd, sizeof(rd_t));
        // bgp_rd_origin_set(&rd1, RD_ORIGIN_UNKNOWN);
        // bgp_rd_origin_set(&rd2, RD_ORIGIN_UNKNOWN);

        // // Print the actual hex values in memory
        // printf("Hex dump of nmct2->rd:\n");
        // print_hex(&rd1, sizeof(rd_t));

        // printf("Hex dump of &info->attr_extra->rd:\n");
        // print_hex(&rd2, sizeof(rd_t));  

        if (!memcmp(&rd1, &rd2, sizeof(rd_t))) {
	  no_match--;
          Log(LOG_INFO, "INFO ( %s/config/BMP ): RD MATCHED ON NLRI [vpnv4 extension]!\n", config.name);
        }
      }
      /* RD location when decoded from Peer Distinguisher */
      else {
	if (info->bmed.id == BGP_MSG_EXTRA_DATA_BMP) {
	  struct bmp_chars *bmed_bmp = (struct bmp_chars *) info->bmed.data;

	  if (bmed_bmp && !memcmp(&bmed_bmp->rd, nmct2->rd, sizeof(rd_t))) {
            Log(LOG_INFO, "INFO ( %s/config/BMP ): RD MATCHED ON NLRI [BMP PD]!\n", config.name);
            Log(LOG_INFO, "INFO ( %s/config/BMP ): |__--> rib_type = %d\n", config.name, bmed_bmp->rib_type);
	    no_match--;
	  }
	}
      }
    }

    if (nmct2->peer->cap_add_paths.cap[nmct2->afi][nmct2->safi]) {
      if (info->attr && nmct2->peer_dst_ip) {
	if (info->attr->mp_nexthop.family) {
	  if (!host_addr_cmp(&info->attr->mp_nexthop, nmct2->peer_dst_ip)) {
	    no_match--;
	  }
	}
        else if (info->attr->nexthop.s_addr && nmct2->peer_dst_ip->family == AF_INET) {
          if (info->attr->nexthop.s_addr == nmct2->peer_dst_ip->address.ipv4.s_addr) {
	    no_match--;
	  }
        }
      }
    }

    if (!no_match) return FALSE;
  }

  return TRUE;
}
