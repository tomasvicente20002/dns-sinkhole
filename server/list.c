#include "list.h"

Node* get_new_node()
{
	Node* ptr = malloc(sizeof(Node));

	if (ptr != NULL)
	{
        ptr->value = NULL;
		ptr->next = NULL;
        ptr->prev = NULL;
	}

	return ptr;
}

BOOL add_to_list(Node**head, void * value)
{
    if(value == NULL)
        return FALSE;

    Node*ptr;

    if(*head == NULL)
    {
        ptr = get_new_node();
        ptr->value = value;
        *head = ptr;
        return TRUE;
    }
    
    ptr = *head;
    while (ptr->next != NULL)    
        ptr = ptr->next;
    
    ptr->next = get_new_node();
    ptr->next->value = value;
    return TRUE;
}


const void* search_from_list(Node *list,const void*value,  BOOL compare_function(const void*,const void*))
{
    if(list == NULL || compare_function == NULL)
        return FALSE; 

    Node* ptr = list;
    while (ptr != NULL)
    {
        if(compare_function(ptr->value, value))       
            return ptr->value;   
        ptr = ptr->next;
    }

    return NULL;
    
}