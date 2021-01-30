#include "matrix_session_extract.h"
#include <olm/olm.h>
#include <glib.h>
#include <gmodule.h>

int decrypt_olm() {
    GHashTable *table = g_hash_table_new(g_str_hash, g_str_equal);

    // Iterate sessions in JSON and put in hashmap
    void *memory = malloc(olm_inbound_group_session_size());
    OlmInboundGroupSession *session = olm_inbound_group_session(memory);
    olm_import_inbound_group_session(session, "2324", 3);
    olm_clear_inbound_group_session(session);

    g_hash_table_insert(table, "test", "memory");
    g_hash_table_insert(table, "lust", "mummaray");

    printf("%s\n", (char *)g_hash_table_lookup(table, "test"));

    g_hash_table_destroy(table);

    return 0;
}
