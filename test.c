#include "test.h"
#include <stdio.h>

int main (void) {
  GA_json* j;
  GA_get_networks(&j);
  char result[1000];
  GA_convert_json_to_string(j, &result);
  printf("result: %s\n\n\n", result);

  GA_destroy_json(j);
  GA_convert_json_to_string(j, &result);
  printf("result2: %s\n\n\n", result);

  GA_json* j2;
  char jsonstr[] = "{\"hello\":123,\"world\":99999}";
  printf("jsonstr: %s\n\n\n", jsonstr);
  GA_convert_string_to_json(jsonstr, &j2);

  GA_convert_json_to_string(j2, &result);
  printf("result3: %s\n\n\n", result);

  char result2[50];
  GA_convert_json_value_to_string(j2, "hello", result2);
  printf("result4: %s\n\n\n", result2);

  uint32_t result3;
  GA_convert_json_value_to_uint32(j2, "world", &result3);
  printf("result5: %d\n\n\n", result3);
}
