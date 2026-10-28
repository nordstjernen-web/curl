/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"

/* The SQLite cookie database, CURLOPT_COOKIEDB: cookies received by one
   handle are seen by another handle using the same database, "ALL" clears
   the database, and a handle picks up cookies another handle stored after
   it opened the database. */

static CURLcode t1927_get(CURL *curl, const char *URL, int num)
{
  char *url = curl_maprintf("%s%04d", URL, num);
  CURLcode result;
  if(!url)
    return TEST_ERR_MAJOR_BAD;
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curlx_free(url);
  result = curl_easy_perform(curl);
  if(result)
    curl_mfprintf(stderr, "request %d failed: %d\n", num, (int)result);
  return result;
}

static CURL *t1927_init(const char *db)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_COOKIEDB, db);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  }
  return curl;
}

static CURLcode test_lib1927(const char *URL)
{
  CURLcode result = CURLE_OK;
  CURL *a = NULL, *b = NULL, *d = NULL, *e = NULL;
  const char *db = libtest_arg2;

  curl_global_init(CURL_GLOBAL_ALL);

  a = t1927_init(db);
  if(!a) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  /* 1: the server sets cookies, 2: they are sent back */
  result = t1927_get(a, URL, 1);
  if(!result)
    result = t1927_get(a, URL, 2);
  if(result)
    goto test_cleanup;
  curl_easy_cleanup(a);
  a = NULL;

  /* 3: a new handle finds the cookies in the database */
  b = t1927_init(db);
  if(!b) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  result = t1927_get(b, URL, 3);
  if(result)
    goto test_cleanup;
  /* 4: "ALL" clears the database too */
  curl_easy_setopt(b, CURLOPT_COOKIELIST, "ALL");
  result = t1927_get(b, URL, 4);
  if(result)
    goto test_cleanup;

  /* 5: another handle sees an empty database */
  e = t1927_init(db);
  if(!e) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  result = t1927_get(e, URL, 5);
  if(result)
    goto test_cleanup;

  /* 6: a third handle receives a cookie, written through to the database */
  d = t1927_init(db);
  if(!d) {
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  result = t1927_get(d, URL, 6);
  if(result)
    goto test_cleanup;

  /* 7: the handle that opened the database earlier sends it */
  result = t1927_get(e, URL, 7);

test_cleanup:
  curl_easy_cleanup(a);
  curl_easy_cleanup(b);
  curl_easy_cleanup(d);
  curl_easy_cleanup(e);
  curl_global_cleanup();
  return result;
}
