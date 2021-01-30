#include "matrix_session_extract.h"
#include <cjson/cJSON.h>
#include <glib.h>
#include <gmodule.h>
#include <olm/olm.h>

void consumer(gpointer key, gpointer value, gpointer user_data) {
  printf("%s: %s\n", key, value);
  olm_clear_inbound_group_session(value);
}

int decrypt_olm(char *session_string, size_t session_len, char *messages_string,
                size_t messages_len) {

  cJSON *sessions_json = cJSON_ParseWithLength(session_string, session_len);
  cJSON *session_json;
  // printf("%s\n", cJSON_Print(sessions_json));

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
  // printf("%s\n", cJSON_Print(msgs_json));

  size_t msgs_len = cJSON_GetArraySize(msgs_json);
  char **plaintext_msgs = malloc(msgs_len * sizeof(char *));
  char **plaintext_ptr = plaintext_msgs;

  cJSON_ArrayForEach(msg_json, msgs_json) {
    // char *msg;
    cJSON *content = cJSON_GetObjectItem(msg_json, "content");
    cJSON *session_id_json = cJSON_GetObjectItem(content, "session_id");

    if (!session_id_json) {
      cJSON_free(content);
      cJSON_free(session_id_json);
      cJSON *unsign = cJSON_GetObjectItem(msg_json, "unsigned");
      cJSON *redac;
      if (unsign) {
        redac = cJSON_GetObjectItem(unsign, "redacted_because");
        content = cJSON_GetObjectItem(redac, "content");
      } else {
        redac = cJSON_GetObjectItem(msg_json, "redacted_because");
        content = cJSON_GetObjectItem(redac, "content");
      }
      cJSON_free(redac);
      cJSON_free(unsign);
      session_id_json = cJSON_GetObjectItem(content, "session_id");
    }

    char *session_id = session_id_json->valuestring;

    cJSON *ciphertext_json = cJSON_GetObjectItem(content, "ciphertext");
    char *ciphertext = ciphertext_json->valuestring;

    size_t plaintext_len = strlen(ciphertext) * 10 * sizeof(char);
    char *plaintext = malloc(plaintext_len);

    OlmSession * session = g_hash_table_lookup(table, session_id);
    printf("loop done\n");
    olm_decrypt(session,
                OLM_MESSAGE_TYPE_MESSAGE, ciphertext, strlen(ciphertext),
                plaintext, plaintext_len);

    cJSON_free(session_id_json);
    cJSON_free(ciphertext_json);
    free(session_id);
    free(ciphertext);

    *plaintext_msgs++ = plaintext;

    free(plaintext);
  }

  cJSON_free(msg_json);
  cJSON_free(msgs_json);

  g_hash_table_foreach(table, consumer, NULL);
  g_hash_table_destroy(table);

  while (plaintext_ptr < plaintext_msgs) {
    printf("%s\n", *plaintext_ptr++);
  }

  return 0;
}
