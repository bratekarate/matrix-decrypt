#include "matrix_session_extract.h"
#include <glib.h>
#include <gmodule.h>
#include <olm/olm.h>

void consumer(gpointer key, gpointer value, gpointer user_data) {
  olm_clear_inbound_group_session(value);
}

char **decrypt_olm(char *session_string, size_t session_len,
                   char *messages_string, size_t messages_len,
                   char **plaintext_msgs) {

  cJSON *sessions_json = cJSON_ParseWithLength(session_string, session_len);
  cJSON *session_json;

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
  cJSON_free(sessions_json);
  cJSON_free(session_json);

  cJSON *msgs_json = cJSON_ParseWithLength(messages_string, messages_len);
  cJSON *msg_json;

  cJSON_ArrayForEach(msg_json, msgs_json) {
    cJSON *content = cJSON_GetObjectItem(msg_json, "content");
    cJSON *session_id_json = cJSON_GetObjectItem(content, "session_id");

    if (!session_id_json) {
      cJSON *unsign = cJSON_GetObjectItem(msg_json, "unsigned");
      cJSON *redac;
      if (unsign) {
        redac = cJSON_GetObjectItem(unsign, "redacted_because");
        if (!redac) {
          continue;
        }
        content = cJSON_GetObjectItem(redac, "content");
      } else {
        redac = cJSON_GetObjectItem(msg_json, "redacted_because");
        if (!redac) {
          continue;
        }
        content = cJSON_GetObjectItem(redac, "content");
      }
      if (!content) {
        continue;
      }
      session_id_json = cJSON_GetObjectItem(content, "session_id");
    }

    char *session_id = session_id_json->valuestring;

    cJSON *ciphertext_json = cJSON_GetObjectItem(content, "ciphertext");
    char *ciphertext = ciphertext_json->valuestring;

    size_t plaintext_len = strlen(ciphertext) * 10 * sizeof(char);
    char *plaintext = malloc(plaintext_len);

    OlmInboundGroupSession *session = g_hash_table_lookup(table, session_id);
    uint32_t *msg_index = malloc(100 * sizeof(uint32_t));
    size_t len = olm_group_decrypt(session, (uint8_t *)ciphertext, strlen(ciphertext),
                      (uint8_t *)plaintext, plaintext_len, msg_index);

    plaintext[len] = '\0';

    *plaintext_msgs++ = plaintext;
    printf("%s\n", plaintext);
  }

  cJSON_free(msg_json);
  cJSON_free(msgs_json);

  g_hash_table_foreach(table, consumer, NULL);
  g_hash_table_destroy(table);

  return plaintext_msgs;
}
