
#include "mylib.h"

typedef struct Node_st {
  void *value;
  struct Node_st* prev;
  struct Node_st* next;
} Node;

Node* get_new_node();
BOOL add_to_list(Node**head, void * value);
const void* search_from_list(Node *list,const void*value,  BOOL compare_function(const void*,const void*));