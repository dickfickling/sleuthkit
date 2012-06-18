/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk_hashdb_i.h"

/**
 * \file tm_lookup.c
 * Contains the generic hash database creation and lookup code.
 */

static sqlite3_stmt *m_insertStmt;
static sqlite3_stmt *m_selectStmt;


int
static attempt(int resultCode, int expectedResultCode,
    const char *errfmt, TSK_HDB_INFO * hdb_info)
{
    if (resultCode != expectedResultCode) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, sqlite3_errmsg(hdb_info->hIdx_sqlite), resultCode);
        return 1;
    }
    return 0;
}



/**
 * Execute a statement and sets TSK error values on error 
 * @returns 1 on error, 0 on success
 */
static int
attempt_exec_err(const char *sql, int (*callback) (void *, int,
        char **, char **), void *callback_arg, const char *errfmt, TSK_HDB_INFO * hdb_info)
{
    char *
        errmsg;

    if (!hdb_info->hIdx_sqlite)
        //TODO: error handling
        return 1;

    if (sqlite3_exec(hdb_info->hIdx_sqlite, sql, callback, callback_arg,
            &errmsg) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr(errfmt, errmsg);
        sqlite3_free(errmsg);
        return 1;
    }
    return 0;
}

/**
 * Execute a statement.  
 * @returns 1 on error, 0 on success
 */
static int
attempt_exec(const char *sql, const char *errfmt, TSK_HDB_INFO * hdb_info)
{
    return attempt_exec_err(sql, NULL, NULL, errfmt, hdb_info);
}


/**
 * @returns 1 on error, 0 on success
 */
static int
prepare_stmt(const char *sql, sqlite3_stmt ** ppStmt, TSK_HDB_INFO * hdb_info)
{
    if (sqlite3_prepare_v2(hdb_info->hIdx_sqlite, sql, -1, ppStmt, NULL) != SQLITE_OK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_AUTO_DB);
        tsk_error_set_errstr("Error preparing SQL statement: %s\n", sql);
        tsk_error_print(stderr);
        return 1;
    }
    return 0;
}

static uint8_t
tsk_hdb_begin_transaction(TSK_HDB_INFO * hdb_info) {
    return attempt_exec("BEGIN", "Error beginning transaction %s\n", hdb_info);
}

static uint8_t
tsk_hdb_commit_transaction(TSK_HDB_INFO * hdb_info) {
    return attempt_exec("COMMIT", "Error committing transaction %s\n", hdb_info);
}

/**
 * Setup the hash-type specific information (such as length, index entry
 * sizes, index name etc.) in the HDB_INFO structure.
 *
 * @param hdb_info Structure to fill in.
 * @param htype Hash type being used
 * @return 1 on error and 0 on success
 */
static uint8_t
hdb_setuphash(TSK_HDB_INFO * hdb_info, uint8_t htype)
{
    size_t flen;

    if (hdb_info->hash_type != 0) {
        return 0;
    }

    /* Make the name for the index file */
    flen = TSTRLEN(hdb_info->db_fname) + 32;
    hdb_info->idx_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (hdb_info->idx_fname == NULL) {
        return 1;
    }

    /* Get hash type specific information */
    switch (htype) {
    case TSK_HDB_HTYPE_MD5_ID:
        hdb_info->hash_type = TSK_HDB_HTYPE_MD5_ID;
        hdb_info->hash_len = TSK_HDB_HTYPE_MD5_LEN;
        hdb_info->idx_llen = TSK_HDB_IDX_LEN(htype);
        TSNPRINTF(hdb_info->idx_fname, flen,
                  _TSK_T("%s-%") PRIcTSK _TSK_T(".idx"),
                  hdb_info->db_fname, TSK_HDB_HTYPE_MD5_STR);
        return 0;
    case TSK_HDB_HTYPE_SHA1_ID:
        hdb_info->hash_type = TSK_HDB_HTYPE_SHA1_ID;
        hdb_info->hash_len = TSK_HDB_HTYPE_SHA1_LEN;
        hdb_info->idx_llen = TSK_HDB_IDX_LEN(htype);
        TSNPRINTF(hdb_info->idx_fname, flen,
                  _TSK_T("%s-%") PRIcTSK _TSK_T(".idx"),
                  hdb_info->db_fname, TSK_HDB_HTYPE_SHA1_STR);
        return 0;
    }

    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr(
             "hdb_setuphash: Invalid hash type as argument: %d", htype);
    return 1;
}


/** Initialize the TSK hash DB index file. This creates the intermediate file,
 * which will have entries added to it.  This file must be sorted before the 
 * process is finished.
 *
 * @param hdb_info Hash database state structure
 * @param htype String of index type to create
 *
 * @return 1 on error and 0 on success
 *
 */
uint8_t
tsk_hdb_idxinitialize(TSK_HDB_INFO * hdb_info, TSK_TCHAR * htype)
{
    char dbtmp[32];
    char stmt[1024];
    int i;
    char * insertStmt;


    /* Use the string of the index/hash type to figure out some
     * settings */

    // convert to char -- cheating way to deal with WCHARs..
    for (i = 0; i < 31 && htype[i] != '\0'; i++) {
        dbtmp[i] = (char) htype[i];
    }
    dbtmp[i] = '\0';

    if (strcmp(dbtmp, TSK_HDB_DBTYPE_NSRL_MD5_STR) == 0) {

        if (hdb_info->db_type != TSK_HDB_DBTYPE_NSRL_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_NSRL_ID);
            return 1;
        }
        hdb_setuphash(hdb_info, TSK_HDB_HTYPE_MD5_ID);
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_NSRL_SHA1_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_NSRL_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_NSRL_ID);
            return 1;
        }
        hdb_setuphash(hdb_info, TSK_HDB_HTYPE_SHA1_ID);
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_MD5SUM_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_MD5SUM_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_MD5SUM_ID);
            return 1;
        }
        hdb_setuphash(hdb_info, TSK_HDB_HTYPE_MD5_ID);
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_HK_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_HK_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_HK_ID);
            return 1;
        }
        hdb_setuphash(hdb_info, TSK_HDB_HTYPE_MD5_ID);
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_ENCASE_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_ENCASE_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_ENCASE_ID);
            return 1;
        }
        hdb_setuphash(hdb_info, TSK_HDB_HTYPE_MD5_ID);
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "hdb_idxinitialize: Unknown database type request: %s",
                 dbtmp);
        return 1;
    }

    if(!hdb_info->hIdx_sqlite) {
        if (attempt(sqlite3_open16(hdb_info->idx_fname, &(hdb_info->hIdx_sqlite)),
                SQLITE_OK,
                "Can't open database: %s\n", hdb_info)) {
            sqlite3_close(hdb_info->hIdx_sqlite);
            return 1;
        }
    }

    sqlite3_extended_result_codes(hdb_info->hIdx_sqlite, 1);

    if (attempt_exec("PRAGMA synchronous =  OFF;",
            "Error setting PRAGMA synchronous: %s\n", hdb_info)) {
        return 1;
    }

    if (attempt_exec
        ("CREATE TABLE hashset_properties (name TEXT, value TEXT);",
            "Error creating hashset_properties table: %s\n", hdb_info)) {
        return 1;
    }

    snprintf(stmt, 1024,
        "INSERT INTO hashset_properties (name, value) VALUES ('%s', '%s');",
        IDX_SCHEMA_VER, IDX_VERSION_NUM);
    if (attempt_exec(stmt, "Error adding schema info to hashset_properties table: %s\n", hdb_info)) {
        return 1;
    }

    snprintf(stmt, 1024,
        "INSERT INTO hashset_properties (name, value) VALUES ('%s', '%s');",
        IDX_HASHSET_NAME, hdb_info->db_name);
    if (attempt_exec(stmt, "Error adding name to hashset_properties table: %s\n", hdb_info)) {
        return 1;
    }

    if (attempt_exec
        ("CREATE TABLE hashset_hashes (md5 BINARY(16), sha1 BINARY(20), database_offset INTEGER);",
            "Error creating hashset_hashes table: %s\n", hdb_info)) {
        return 1;
    }

    if(hdb_info->hash_type == TSK_HDB_HTYPE_MD5_ID) {
        insertStmt = "INSERT INTO hashset_hashes (md5, database_offset) VALUES (?, ?);";
    } else if(hdb_info->hash_type == TSK_HDB_HTYPE_SHA1_ID) {
        insertStmt = "INSERT INTO hashset_hashes (sha1, database_offset) VALUES (?, ?);";
    } else {
        return 1;
    }


    if(prepare_stmt(insertStmt, &m_insertStmt, hdb_info)) {
        return 1;
    }

    if(tsk_hdb_begin_transaction(hdb_info)) {
        return 1;
    }

    return 0;
}

/**
 * Add a string entry to the intermediate index file.
 *
 * @param hdb_info Hash database state info
 * @param hvalue String of hash value to add
 * @param offset Byte offset of hash entry in original database.
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_hdb_idxaddentry(TSK_HDB_INFO * hdb_info, char *hvalue,
                    TSK_OFF_T offset)
{
    const size_t len = (hdb_info->hash_len)/2;
    unsigned char * hash = (unsigned char *) malloc(len+1);
    size_t count = 0;

    if(strlen(hvalue) != hdb_info->hash_len) {
        //TODO: error handling
        free(hash);
        return 1;
    }

    // Convert string hash to binary
    for(count = 0; count < len; count++) {
        sscanf(hvalue, "%2hx", &(hash[count]));
        hvalue += 2 * sizeof(char);
    }

    return tsk_hdb_idxaddentry_bin(hdb_info, hash, len, offset);
}

/**
 * Add a binary entry to the intermediate index file.
 *
 * @param hdb_info Hash database state info
 * @param hvalue Array of integers of hash value to add
 * @param hlen Number of bytes in hvalue
 * @param offset Byte offset of hash entry in original database.
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_hdb_idxaddentry_bin(TSK_HDB_INFO * hdb_info, unsigned char *hvalue, int hlen,
                    TSK_OFF_T offset)
{

    if(attempt(sqlite3_bind_blob(m_insertStmt, 1, hvalue, hlen, free),
        SQLITE_OK,
        "Error binding binary blob: %s\n",
        hdb_info) ||
        attempt(sqlite3_bind_int64(m_insertStmt, 2, offset),
        SQLITE_OK,
        "Error binding name text: %s\n",
        hdb_info) ||
        attempt(sqlite3_step(m_insertStmt), SQLITE_DONE, "Error stepping: %s\n", hdb_info) ||
        attempt(sqlite3_reset(m_insertStmt), SQLITE_OK, "Error resetting: %s\n", hdb_info)) {
        return 1;
    }

    return 0;
}

/**
 * Finalize index creation process by sorting the index and removing the
 * intermediate temp file.
 *
 * @param hdb_info Hash database state info structure.
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_hdb_idxfinalize(TSK_HDB_INFO * hdb_info)
{
    if(tsk_hdb_commit_transaction(hdb_info)) {
        //TODO: Error handling
        return 1;
    }
    return attempt_exec("CREATE INDEX hashset_md5_index ON hashset_hashes(md5);",
        "Error creating hashset_md5_index on md5: %s\n", hdb_info);
    return attempt_exec("CREATE INDEX hashset_sha1_index ON hashset_hashes(sha1);",
        "Error creating hashset_sha1_index on sha1: %s\n", hdb_info);
}


/** \internal
 * Setup the internal variables to read an index. This
 * opens the index and sets the needed size information.
 *
 * @param hdb_info Hash database to analyze
 * @param hash The hash type that was used to make the index.
 *
 * @return 1 on error and 0 on success
 */
static uint8_t
hdb_setupindex(TSK_HDB_INFO * hdb_info, uint8_t htype)
{
    char * selectStmt;
 

    if (hdb_info->hIdx_sqlite != NULL) {
        return 0;
    }

    // Lock for lazy load of hIdx and lazy alloc of idx_lbuf.
    tsk_take_lock(&hdb_info->lock);

    if ((htype != TSK_HDB_HTYPE_MD5_ID)
        && (htype != TSK_HDB_HTYPE_SHA1_ID)) {
        tsk_release_lock(&hdb_info->lock);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "hdb_setupindex: Invalid hash type : %d", htype);
        return 1;
    }

    if (hdb_setuphash(hdb_info, htype)) {
        tsk_release_lock(&hdb_info->lock);
        return 1;
    }

        /* Verify the index exists and open it */
#ifdef TSK_WIN32
    {

        if (-1 == GetFileAttributes(hdb_info->idx_fname)) {
            tsk_release_lock(&hdb_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                     "hdb_setupindex: Error finding index file: %"PRIttocTSK,
                     hdb_info->idx_fname);
            return 1;
        }
    }
#else
    {
        struct stat sb;
        if (stat(hdb_info->idx_fname, &sb) < 0) {
            tsk_release_lock(&hdb_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                     "hdb_setupindex: Error finding index file: %s",
                     hdb_info->idx_fname);
            return 1;
        }
    }
#endif

    if(!hdb_info->hIdx_sqlite) {
        if (attempt(sqlite3_open16(hdb_info->idx_fname, &(hdb_info->hIdx_sqlite)),
                SQLITE_OK,
                "Can't open database: %s\n", hdb_info)) {
            sqlite3_close(hdb_info->hIdx_sqlite);
            return 1;
        }
    }

    if(htype == TSK_HDB_HTYPE_MD5_ID) {
        selectStmt = "SELECT md5,database_offset from hashset_hashes WHERE md5=? limit 1;";
    } else if(htype == TSK_HDB_HTYPE_SHA1_ID) {
        selectStmt = "SELECT sha1,database_offset from hashset_hashes WHERE sha1=? limit 1;";
    }

    if(prepare_stmt(selectStmt, &m_selectStmt, hdb_info)) {
        return -1;
    }

    if(tsk_hdb_begin_transaction(hdb_info)) {
        return 1;
    }

    sqlite3_extended_result_codes(hdb_info->hIdx_sqlite, 1);

    tsk_release_lock(&hdb_info->lock);

    return 0;
}








/**
 * \ingroup hashdblib
 * Search the index for a text/ASCII hash value
 *
 * @param hdb_info Open hash database (with index)
 * @param hash Hash value to search for (NULL terminated string)
 * @param flags Flags to use in lookup
 * @param action Callback function to call for each hash db entry 
 * (not called if QUICK flag is given)
 * @param ptr Pointer to data to pass to each callback
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t
tsk_hdb_lookup_str(TSK_HDB_INFO * hdb_info, const char *hash,
                   TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action,
                   void *ptr)
{
    const size_t len = strlen(hash)/2;
    unsigned char * hashBlob = (unsigned char *) malloc(len+1);
    const char * pos = hash;
    size_t count = 0;
    size_t i;
    uint8_t htype;


    /* Sanity checks on the hash input */
    if (strlen(hash) == TSK_HDB_HTYPE_MD5_LEN) {
        htype = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strlen(hash) == TSK_HDB_HTYPE_SHA1_LEN) {
        htype = TSK_HDB_HTYPE_SHA1_ID;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "hdb_lookup: Invalid hash length: %s", hash);
        free(hashBlob);
        return -1;
    }

    for (i = 0; i < strlen(hash); i++) {
        if (isxdigit((int) hash[i]) == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_lookup: Invalid hash value (hex only): %s",
                     hash);
            free(hashBlob);
            return -1;
        }
    }

    for(count = 0; count < len; count++) {
        sscanf(pos, "%2hx", &(hashBlob[count]));
        pos += 2 * sizeof(char);
    }
    return tsk_hdb_lookup_raw(hdb_info, hashBlob, len, flags, action, ptr);

}

/**
 * \ingroup hashdblib
 * Search the index for the given hash value given (in binary form).
 *
 * @param hdb_info Open hash database (with index)
 * @param hash Array with binary hash value to search for
 * @param len Number of bytes in binary hash value
 * @param flags Flags to use in lookup
 * @param action Callback function to call for each hash db entry 
 * (not called if QUICK flag is given)
 * @param ptr Pointer to data to pass to each callback
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t
tsk_hdb_lookup_raw(TSK_HDB_INFO * hdb_info, uint8_t * hash, uint8_t len,
                   TSK_HDB_FLAG_ENUM flags,
                   TSK_HDB_LOOKUP_FN action, void *ptr)
{
    char hashbuf[TSK_HDB_HTYPE_SHA1_LEN + 1];
    int i;
    static const char hex[] = "0123456789abcdef";
    TSK_OFF_T offset;

    if (hdb_setupindex(hdb_info, TSK_HDB_HTYPE_MD5_ID)) {
        return -1;
    }

    /* Sanity check */
    if ((hdb_info->hash_len)/2 != len) { // len in bytes * 2 letters to display each byte
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
            "hdb_lookup: Hash passed is different size than expected (%d vs %Zd)",
            hdb_info->hash_len, len);
        return -1;
    }

    if(attempt(sqlite3_bind_blob(m_selectStmt, 1, hash, len, free), 
        SQLITE_OK,
        "Error binding binary blob: %s\n",
        hdb_info)) {
            return -1;
    }

    if(sqlite3_step(m_selectStmt) == SQLITE_ROW) {
        if ((flags & TSK_HDB_FLAG_QUICK)
            || (hdb_info->db_type == TSK_HDB_DBTYPE_IDXONLY_ID)) {
                sqlite3_reset(m_selectStmt);
                return 1;
        } else {
            for (i = 0; i < len; i++) {
                hashbuf[2 * i] = hex[(hash[i] >> 4) & 0xf];
                hashbuf[2 * i + 1] = hex[hash[i] & 0xf];
            }
            hashbuf[2 * len] = '\0';

            offset = sqlite3_column_int64(m_selectStmt, 1);
            sqlite3_reset(m_selectStmt);
            if (hdb_info->
                getentry(hdb_info, hashbuf, offset, flags, action, ptr)) {
                    tsk_error_set_errstr2( "hdb_lookup");
                    sqlite3_reset(m_selectStmt);
                    return -1;
            }
            return 1;
        }
    }
    
    sqlite3_reset(m_selectStmt);

    return 0;

}

/**
* \ingroup hashdblib
* Determine if the open hash database has an index.
 *
 * @param hdb_info Hash database to consider
 * @param htype Hash type that index should be of
 *
 * @return 1 if index exists and 0 if not
 */
uint8_t
tsk_hdb_hasindex(TSK_HDB_INFO * hdb_info, uint8_t htype)
{
    /* Check if the index is already open, and 
     * try to open it if not */
    if (hdb_setupindex(hdb_info, htype))
        return 0;
    else
        return 1;
}



/**
 * \ingroup hashdblib
 * Open a hash database. 
 *
 * @param db_file Path to database (even if only an index exists).
 * @param flags Flags for opening the database.  
 *
 * @return Poiner to hash database state structure or NULL on error
 */
TSK_HDB_INFO *
tsk_hdb_open(TSK_TCHAR * db_file, TSK_HDB_OPEN_ENUM flags)
{
    TSK_HDB_INFO *hdb_info;
    size_t flen;
    FILE *hDb;
    TSK_HDB_DBTYPE_ENUM dbtype = (TSK_HDB_DBTYPE_ENUM) NULL;

    if ((flags & TSK_HDB_OPEN_IDXONLY) == 0) {
        /* Open the database file */
#ifdef TSK_WIN32
        {
            HANDLE hWin;

            if ((hWin = CreateFile(db_file, GENERIC_READ,
                                   FILE_SHARE_READ, 0, OPEN_EXISTING, 0,
                                   0)) == INVALID_HANDLE_VALUE) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_OPEN);
                tsk_error_set_errstr(
                         "hdb_open: Error opening database file: %S",
                         db_file);
                return NULL;
            }
            hDb =
                _fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "r");
            if (hDb == NULL) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_OPEN);
                tsk_error_set_errstr(
                         "hdb_open: Error converting Windows handle to C handle");
                return NULL;
            }
        }
#else
        if (NULL == (hDb = fopen(db_file, "r"))) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                     "hdb_open: Error opening database file: %s", db_file);
            return NULL;
        }
#endif

        /* Try to figure out what type of DB it is */
        if (nsrl_test(hDb)) {
            dbtype = TSK_HDB_DBTYPE_NSRL_ID;
        }
        if (md5sum_test(hDb)) {
            if (dbtype != 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                         "hdb_open: Error determining DB type (MD5sum)");
                return NULL;
            }
            dbtype = TSK_HDB_DBTYPE_MD5SUM_ID;
        }
        if (encase_test(hDb)) {
            if (dbtype != 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                         "hdb_open: Error determining DB type (EnCase)");
                return NULL;
            }
            dbtype = TSK_HDB_DBTYPE_ENCASE_ID;
        }
        if (hk_test(hDb)) {
            if (dbtype != 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                         "hdb_open: Error determining DB type (HK)");
                return NULL;
            }
            dbtype = TSK_HDB_DBTYPE_HK_ID;
        }
        if (dbtype == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
            tsk_error_set_errstr(
                     "hdb_open: Error determining DB type");
            return NULL;
        }
        fseeko(hDb, 0, SEEK_SET);
    }
    else {
        dbtype = TSK_HDB_DBTYPE_IDXONLY_ID;
        hDb = NULL;
    }

    if ((hdb_info =
         (TSK_HDB_INFO *) tsk_malloc(sizeof(TSK_HDB_INFO))) == NULL)
        return NULL;

    hdb_info->hDb = hDb;

    /* Copy the database name into the structure */
    flen = TSTRLEN(db_file) + 8;        // + 32;

    hdb_info->db_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (hdb_info->db_fname == NULL) {
        free(hdb_info);
        return NULL;
    }
    TSTRNCPY(hdb_info->db_fname, db_file, flen);

    
    hdb_info->hash_type = (TSK_HDB_HTYPE_ENUM) NULL;
    hdb_info->hash_len = 0;
    hdb_info->idx_fname = NULL;

    hdb_info->uns_fname = NULL;
    hdb_info->hIdxTmp = NULL;
    hdb_info->hIdx = NULL;
    hdb_info->hIdx_sqlite = NULL;

    hdb_info->idx_size = 0;
    hdb_info->idx_off = 0;

    hdb_info->idx_lbuf = NULL;

    tsk_init_lock(&hdb_info->lock);

    /* Get database specific information */
    hdb_info->db_type = dbtype;
    switch (dbtype) {
    case TSK_HDB_DBTYPE_NSRL_ID:
        nsrl_name(hdb_info);
        hdb_info->getentry = nsrl_getentry;
        hdb_info->makeindex = nsrl_makeindex;
        break;

    case TSK_HDB_DBTYPE_MD5SUM_ID:
        md5sum_name(hdb_info);
        hdb_info->getentry = md5sum_getentry;
        hdb_info->makeindex = md5sum_makeindex;
        break;

    case TSK_HDB_DBTYPE_ENCASE_ID:
        encase_name(hdb_info);
        hdb_info->getentry = encase_getentry;
        hdb_info->makeindex = encase_makeindex;
        break;

    case TSK_HDB_DBTYPE_HK_ID:
        hk_name(hdb_info);
        hdb_info->getentry = hk_getentry;
        hdb_info->makeindex = hk_makeindex;
        break;

    case TSK_HDB_DBTYPE_IDXONLY_ID:
        idxonly_name(hdb_info);
        hdb_info->getentry = idxonly_getentry;
        hdb_info->makeindex = idxonly_makeindex;
        break;

    default:
        return NULL;
    }


    return hdb_info;
}

/**
 * \ingroup hashdblib
 * Close an open hash database.
 *
 * @param hdb_info database to close
 */
void
tsk_hdb_close(TSK_HDB_INFO * hdb_info)
{
    if (hdb_info->hIdx)
        fclose(hdb_info->hIdx);

    if (hdb_info->hIdxTmp)
        fclose(hdb_info->hIdxTmp);
    // @@@ Could delete temp file too...

    if (hdb_info->idx_lbuf != NULL)
        free(hdb_info->idx_lbuf);

    if (hdb_info->db_fname)
        free(hdb_info->db_fname);

    if (hdb_info->uns_fname)
        free(hdb_info->uns_fname);

    if (hdb_info->idx_fname)
        free(hdb_info->idx_fname);

    if (hdb_info->hDb)
        fclose(hdb_info->hDb);

    if (m_insertStmt) {
        sqlite3_finalize(m_insertStmt);
        m_insertStmt = NULL;
    }

    if (m_selectStmt) {
        sqlite3_finalize(m_selectStmt);
        m_selectStmt = NULL;
    }

    if(tsk_hdb_commit_transaction(hdb_info)) {
    }

    if (hdb_info->hIdx_sqlite) {
        sqlite3_close(hdb_info->hIdx_sqlite);
        hdb_info->hIdx_sqlite = NULL;
    }

    tsk_deinit_lock(&hdb_info->lock);

    free(hdb_info);
}

/**
 * \ingroup hashdblib
 * Create an index for an open hash database.
 * @param a_hdb_info Open hash database to index
 * @param a_type Text of hash database type
 * @returns 1 on error
 */
uint8_t
tsk_hdb_makeindex(TSK_HDB_INFO * a_hdb_info, TSK_TCHAR * a_type)
{
    return a_hdb_info->makeindex(a_hdb_info, a_type);
}

/**
 * Set db_name to the name of the database file
 *
 * @param hdb_info the hash database object
 */
void
tsk_hdb_name_from_path(TSK_HDB_INFO * hdb_info)
{
#ifdef TSK_WIN32
    const char PATH_CHAR = '\\';
#else
    const char PATH_CHAR = '/';
#endif
    TSK_TCHAR * begin;
    TSK_TCHAR * end;
    int i;

    hdb_info->db_name[0] = '\0';

    begin = TSTRRCHR(hdb_info->db_fname, PATH_CHAR);
#ifdef TSK_WIN32
    // cygwin can have forward slashes, so try that too on Windows
    if (!begin) {
        begin = TSTRRCHR(hdb_info->db_fname, '/');
    }
#endif

    if (!begin) {
        begin = hdb_info->db_fname;
    }
    else {
        // unlikely since this means that the dbname is "/"
        if (TSTRLEN(begin) == 1)
            return;
        else
            begin++;
    }

    // end points to the byte after the last one we want to use
    if ((TSTRLEN(hdb_info->db_fname) > 4) && (TSTRICMP(&hdb_info->db_fname[TSTRLEN(hdb_info->db_fname)-4], _TSK_T(".idx")) == 0)) 
        end = &hdb_info->db_fname[TSTRLEN(hdb_info->db_fname)-4];
    else
        end = begin + TSTRLEN(begin);
        

    // @@@ TODO: Use TskUTF16_to_UTF8 to properly convert for Windows
    for(i = 0; i < (end-begin); i++)
    {
        hdb_info->db_name[i] = (char) begin[i];
    }

    hdb_info->db_name[i] = '\0';
}