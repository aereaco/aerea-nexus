#ifndef NEXUS_IO_H
#define NEXUS_IO_H

#ifdef __cplusplus
extern "C" {
#endif

/** Returns the Nexus-IO version & native WebView engine string. Free with nexus_io_free_string(). */
char *nexus_io_version(void);

/** Initializes the embedded in-memory nexus-db runtime. Returns 0 on success. */
int nexus_io_init_mem(void);

/** Executes SurrealQL against (ns, db) and returns a JSON array of statement results. Free with nexus_io_free_string(). */
char *nexus_io_query_json(const char *ns, const char *db, const char *surql);

/** Frees a string returned by Nexus-IO FFI functions. */
void nexus_io_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* NEXUS_IO_H */
