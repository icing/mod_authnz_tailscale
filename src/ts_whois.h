/***************************************************************************
 *                                  _   _ ____  _
 * Copyright (C) 2022, Stefan Eissing, <stefan@eissing.org>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#ifndef mod_authnz_tailscale_ts_whois_h
#define mod_authnz_tailscale_ts_whois_h

#define TS_USER_MAXLEN      128

typedef struct {
    char user[TS_USER_MAXLEN+1];
} ts_whois_t;

apr_status_t ts_whois_get(ts_whois_t *whois, request_rec *r, const char *uds_path);

#endif