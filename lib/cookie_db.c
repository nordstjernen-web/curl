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
#include "curl_setup.h"

#if defined(USE_SQLITE) && !defined(CURL_DISABLE_HTTP) && \
  !defined(CURL_DISABLE_COOKIES)

#include <sqlite3.h>

#include "urldata.h"
#include "cookie.h"
#include "cookie_db.h"
#include "curl_trc.h"
#include "llist.h"
#include "curlx/strdup.h"

/*
 * The SQLite cookie store keeps one row per cookie. The in-memory cookies
 * of the CookieInfo are loaded from it and every cookie received from a
 * server is written through to it right away, so several handles and
 * processes can share one store and see each others cookies. "PRAGMA
 * data_version" tells when another connection changed the database, the
 * cookies are then reloaded before they are used.
 */

struct cookie_db {
  sqlite3 *h;
  char *path;
  sqlite3_stmt *st_store;
  sqlite3_stmt *st_remove;
  int data_version;
};

static const char cookie_db_schema[] =
  "CREATE TABLE IF NOT EXISTS cookies ("
  "domain TEXT NOT NULL, "
  "tailmatch INTEGER NOT NULL, "
  "path TEXT NOT NULL, "
  "secure INTEGER NOT NULL, "
  "httponly INTEGER NOT NULL, "
  "expires INTEGER NOT NULL, "
  "name TEXT NOT NULL, "
  "value TEXT NOT NULL, "
  "samesite INTEGER NOT NULL DEFAULT 0, "
  "partitioned INTEGER NOT NULL DEFAULT 0, "
  "partkey TEXT NOT NULL DEFAULT '', "
  "creationtime INTEGER NOT NULL DEFAULT 0, "
  "PRIMARY KEY (domain, tailmatch, path, name, partkey))";

static const char cookie_db_store_sql[] =
  "INSERT OR REPLACE INTO cookies (domain, tailmatch, path, secure, "
  "httponly, expires, name, value, samesite, partitioned, partkey, "
  "creationtime) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

static const char cookie_db_remove_sql[] =
  "DELETE FROM cookies WHERE domain = ?1 AND tailmatch = ?2 AND "
  "path = ?3 AND name = ?4 AND partkey = ?5";

static const char cookie_db_select_sql[] =
  "SELECT domain, tailmatch, path, secure, httponly, expires, name, value, "
  "samesite, partitioned, partkey, creationtime FROM cookies";

static int cookie_db_data_version(struct cookie_db *db)
{
  sqlite3_stmt *st = NULL;
  int version = 0;
  if(sqlite3_prepare_v2(db->h, "PRAGMA data_version", -1, &st, NULL) ==
     SQLITE_OK) {
    if(sqlite3_step(st) == SQLITE_ROW)
      version = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
  }
  return version;
}

static void cookie_db_free(struct cookie_db *db)
{
  if(db) {
    if(db->st_store)
      sqlite3_finalize(db->st_store);
    if(db->st_remove)
      sqlite3_finalize(db->st_remove);
    if(db->h)
      sqlite3_close(db->h);
    curlx_free(db->path);
    curlx_free(db);
  }
}

void Curl_cookie_db_close(struct CookieInfo *ci)
{
  if(ci && ci->db) {
    cookie_db_free(ci->db);
    ci->db = NULL;
  }
}

static const char *cookie_db_text(sqlite3_stmt *st, int col)
{
  const char *s = (const char *)sqlite3_column_text(st, col);
  return s ? s : "";
}

/*
 * Replace the in-memory cookies with the rows of the database.
 */
static CURLcode cookie_db_load(struct Curl_easy *data, struct CookieInfo *ci)
{
  struct cookie_db *db = ci->db;
  sqlite3_stmt *st = NULL;
  CURLcode result = CURLE_OK;
  int rc;

  if(ci->newsession)
    sqlite3_exec(db->h, "DELETE FROM cookies WHERE expires = 0",
                 NULL, NULL, NULL);
  {
    /* drop expired cookies, they are not loaded anyway */
    char sql[80];
    curl_msnprintf(sql, sizeof(sql),
                   "DELETE FROM cookies WHERE expires > 0 AND expires < %"
                   FMT_OFF_T, (curl_off_t)time(NULL));
    sqlite3_exec(db->h, sql, NULL, NULL, NULL);
  }

  rc = sqlite3_prepare_v2(db->h, cookie_db_select_sql, -1, &st, NULL);
  if(rc != SQLITE_OK) {
    infof(data, "[cookies] cannot read database %s: %s", db->path,
          sqlite3_errmsg(db->h));
    return CURLE_OK;
  }

  Curl_cookie_clearall(ci);
  while(sqlite3_step(st) == SQLITE_ROW) {
    struct Cookie *co = curlx_calloc(1, sizeof(*co));
    const char *partkey;
    if(!co) {
      result = CURLE_OUT_OF_MEMORY;
      break;
    }
    co->domain = curlx_strdup(cookie_db_text(st, 0));
    co->tailmatch = !!sqlite3_column_int(st, 1);
    co->path = curlx_strdup(cookie_db_text(st, 2));
    co->secure = !!sqlite3_column_int(st, 3);
    co->httponly = !!sqlite3_column_int(st, 4);
    co->expires = (curl_off_t)sqlite3_column_int64(st, 5);
    co->name = curlx_strdup(cookie_db_text(st, 6));
    co->value = curlx_strdup(cookie_db_text(st, 7));
    co->samesite = (unsigned char)(sqlite3_column_int(st, 8) & 0x3);
    co->partitioned = !!sqlite3_column_int(st, 9);
    partkey = cookie_db_text(st, 10);
    if(*partkey)
      co->partkey = curlx_strdup(partkey);
    co->creationtime = (unsigned int)sqlite3_column_int64(st, 11);
    if(!co->domain || !co->path || !co->name || !co->value ||
       (*partkey && !co->partkey)) {
      curlx_free(co->domain);
      curlx_free(co->path);
      curlx_free(co->name);
      curlx_free(co->value);
      curlx_free(co->partkey);
      curlx_free(co);
      result = CURLE_OUT_OF_MEMORY;
      break;
    }
    result = Curl_cookie_add_loaded(data, ci, co);
    if(result)
      break;
  }
  sqlite3_finalize(st);
  db->data_version = cookie_db_data_version(db);
  CURL_TRC_M(data, "[cookies] loaded %u cookies from %s", ci->numcookies,
             db->path);
  return result;
}

CURLcode Curl_cookie_db_open(struct Curl_easy *data, struct CookieInfo *ci,
                             const char *path)
{
  struct cookie_db *db;
  int rc;

  if(ci->db && !strcmp(ci->db->path, path))
    return Curl_cookie_db_sync(data, ci);
  Curl_cookie_db_close(ci);

  db = curlx_calloc(1, sizeof(*db));
  if(!db)
    return CURLE_OUT_OF_MEMORY;
  db->path = curlx_strdup(path);
  if(!db->path) {
    curlx_free(db);
    return CURLE_OUT_OF_MEMORY;
  }
  rc = sqlite3_open_v2(path, &db->h,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
  if(rc != SQLITE_OK) {
    infof(data, "WARNING: failed to open cookie database \"%s\": %s", path,
          db->h ? sqlite3_errmsg(db->h) : sqlite3_errstr(rc));
    cookie_db_free(db);
    return CURLE_OK;
  }
  sqlite3_busy_timeout(db->h, 2000);
  /* readers do not block writers and vice versa */
  sqlite3_exec(db->h, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
  rc = sqlite3_exec(db->h, cookie_db_schema, NULL, NULL, NULL);
  if(rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(db->h, cookie_db_store_sql, -1, &db->st_store,
                            NULL);
  if(rc == SQLITE_OK)
    rc = sqlite3_prepare_v2(db->h, cookie_db_remove_sql, -1, &db->st_remove,
                            NULL);
  if(rc != SQLITE_OK) {
    infof(data, "WARNING: cannot use cookie database \"%s\": %s", path,
          sqlite3_errmsg(db->h));
    cookie_db_free(db);
    return CURLE_OK;
  }
  ci->db = db;
  return cookie_db_load(data, ci);
}

CURLcode Curl_cookie_db_sync(struct Curl_easy *data, struct CookieInfo *ci)
{
  if(ci && ci->db) {
    int version = cookie_db_data_version(ci->db);
    if(version != ci->db->data_version) {
      CURL_TRC_M(data, "[cookies] database %s changed, reloading",
                 ci->db->path);
      return cookie_db_load(data, ci);
    }
  }
  return CURLE_OK;
}

static int cookie_db_bind_key(sqlite3_stmt *st, const struct Cookie *co)
{
  int rc = sqlite3_bind_text(st, 1, co->domain, -1, SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 2, co->tailmatch ? 1 : 0);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 3, co->path ? co->path : "", -1,
                           SQLITE_STATIC);
  return rc;
}

void Curl_cookie_db_store(struct CookieInfo *ci, const struct Cookie *co)
{
  struct cookie_db *db = ci ? ci->db : NULL;
  sqlite3_stmt *st;
  int rc;

  if(!db || !co->domain || !co->name)
    return;
  st = db->st_store;
  rc = cookie_db_bind_key(st, co);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 4, co->secure ? 1 : 0);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 5, co->httponly ? 1 : 0);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int64(st, 6, (sqlite3_int64)co->expires);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 7, co->name, -1, SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 8, co->value ? co->value : "", -1,
                           SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 9, (int)co->samesite);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int(st, 10, co->partitioned ? 1 : 0);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 11, co->partkey ? co->partkey : "", -1,
                           SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_int64(st, 12, (sqlite3_int64)co->creationtime);
  if(rc == SQLITE_OK)
    (void)sqlite3_step(st);
  sqlite3_reset(st);
  sqlite3_clear_bindings(st);
}

void Curl_cookie_db_remove(struct CookieInfo *ci, const struct Cookie *co)
{
  struct cookie_db *db = ci ? ci->db : NULL;
  sqlite3_stmt *st;
  int rc;

  if(!db || !co->domain || !co->name)
    return;
  st = db->st_remove;
  rc = cookie_db_bind_key(st, co);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 4, co->name, -1, SQLITE_STATIC);
  if(rc == SQLITE_OK)
    rc = sqlite3_bind_text(st, 5, co->partkey ? co->partkey : "", -1,
                           SQLITE_STATIC);
  if(rc == SQLITE_OK)
    (void)sqlite3_step(st);
  sqlite3_reset(st);
  sqlite3_clear_bindings(st);
}

void Curl_cookie_db_clear(struct CookieInfo *ci, bool session_only)
{
  struct cookie_db *db = ci ? ci->db : NULL;
  if(db)
    sqlite3_exec(db->h, session_only ?
                 "DELETE FROM cookies WHERE expires = 0" :
                 "DELETE FROM cookies", NULL, NULL, NULL);
}

void Curl_cookie_db_import(struct CookieInfo *ci)
{
  unsigned int i;
  if(!ci || !ci->db)
    return;
  sqlite3_exec(ci->db->h, "BEGIN", NULL, NULL, NULL);
  for(i = 0; i < COOKIE_HASH_SIZE; i++) {
    struct Curl_llist_node *n;
    for(n = Curl_llist_head(&ci->cookielist[i]); n; n = Curl_node_next(n))
      Curl_cookie_db_store(ci, Curl_node_elem(n));
  }
  sqlite3_exec(ci->db->h, "COMMIT", NULL, NULL, NULL);
}

#endif /* USE_SQLITE && !CURL_DISABLE_HTTP && !CURL_DISABLE_COOKIES */
