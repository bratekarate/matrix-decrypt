#include "matrix_session_extract.h"
#include <cjson/cJSON.h>
#include <glib.h>
#include <gmodule.h>
#include <olm/olm.h>

void consumer(gpointer key, gpointer value, gpointer user_data) {
  printf("%s: %s\n", key, value);
  olm_clear_inbound_group_session(value);
}

int decrypt_olm(char *session_string, size_t session_len) {

  cJSON *sessions_json = cJSON_ParseWithLength(session_string, session_len);
  cJSON *session_json;
  printf("%s\n", cJSON_Print(sessions_json));

  GHashTable *table = g_hash_table_new(g_str_hash, g_str_equal);

  cJSON_ArrayForEach(session_json, sessions_json) {
    void *memory = malloc(olm_inbound_group_session_size());
    OlmInboundGroupSession *session = olm_inbound_group_session(memory);

    char *key = cJSON_GetObjectItem(session_json, "session_key")->valuestring;

    if (olm_import_inbound_group_session(session, key, strlen(key))) {
      printf("%s\n", olm_inbound_group_session_last_error(session));
      continue;
    }

    g_hash_table_insert(
        table, cJSON_GetObjectItem(session_json, "session_id")->valuestring,
        session);
  }

  g_hash_table_foreach(table, consumer, NULL);
  g_hash_table_destroy(table);

  return 0;
}
