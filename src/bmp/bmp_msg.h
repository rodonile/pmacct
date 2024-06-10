/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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

#ifndef BMP_MSG_H
#define BMP_MSG_H

#ifndef PMACCT_GAUZE_BUILD
/* includes */
#include "pmacct_gauze_lib/pmacct_gauze_lib.h"

/* defines */

/* prototypes */
extern u_int32_t bmp_process_packet(char *, u_int32_t, struct bmp_peer *, int *);
extern void bmp_process_msg_init(struct bmp_peer *, ParsedBmp *);
extern void bmp_process_msg_term(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_peer_up(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_peer_down(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_stats(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_route_monitor(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_route_mirror(struct bmp_peer *);

extern Opaque_BmpParsingContext *bmp_parsing_context_get(struct bmp_peer *bmp_peer);
extern Opaque_ContextCache *bmp_context_cache_get();
extern void bmp_parsing_context_clear(struct bmp_peer *bmp_peer);
#endif

#endif //BMP_MSG_H
