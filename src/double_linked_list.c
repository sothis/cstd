#include <stdio.h>
#include <stdlib.h>


typedef struct item_t {
	size_t		data;

	struct item_t*	prev;
	struct item_t*	next;
} item_t;

typedef struct list_t {
	size_t		items;
	struct item_t*	first;
	struct item_t*	last;
} list_t;

list_t list = {0};


struct item_t* create_item(void)
{
	struct item_t* res = calloc(1, sizeof(struct item_t));
	if (!res)
		exit(~0);
	return res;
}

void add_item(struct item_t* item)
{
	if (!list.last) {
		list.first = list.last = item;
	} else {
		list.last->next = item;
		item->prev = list.last;
		list.last = item;
	}
	item->data = list.items;
	list.items++;
}

void traverse_list()
{
	struct item_t* item = list.first;

	while(item) {
		printf("data: %lu\n", item->data);
		item = item->next;
	}
}


void remove_item(struct item_t* item)
{
    if(item == list.first && item == list.last) {
        list.first = 0;
        list.last = 0;
    } else if(item == list.first) {
        list.first = item->next;
        list.first->prev = 0;
    } else if (item == list.last) {
        list.last = item->prev;
        list.last->next = 0;
    } else {
        struct item_t* after = item->next;
        struct item_t* before = item->prev;
        item->next->prev = item->prev;
        item->prev->next = item->next;
    }

    list.items--;
}


int main(int argc, char* argv[], char* envp[])
{
	struct item_t* i = create_item();
	struct item_t* j = create_item();
	struct item_t* k = create_item();

	add_item(i);
	add_item(j);
	add_item(k);
	traverse_list();
	printf("\n");

	remove_item(j);
	//remove_item(k);
	//remove_item(i);
	traverse_list();

	return 0;
}
