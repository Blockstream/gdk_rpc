#include <stdint.h>

typedef struct GA_json GA_json;

int GA_get_networks(GA_json** output);

int GA_convert_json_to_string(const GA_json* json, char** output);
int GA_convert_string_to_json(const char* input, GA_json** output);

int GA_convert_json_value_to_string(const GA_json* json, const char* path, char** output);

int GA_convert_json_value_to_uint32(const GA_json* json, const char* path, uint32_t* output);

int GA_convert_json_value_to_uint64(const GA_json* json, const char* path, uint64_t* output);

int GA_convert_json_value_to_bool(const GA_json* json, const char* path, uint32_t* output);

int GA_convert_json_value_to_json(const GA_json* json, const char* path, GA_json** output);

int GA_destroy_json(GA_json* json);
