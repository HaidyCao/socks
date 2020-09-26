#ifndef C_ARRAY_H
#define C_ARRAY_H

typedef void (*c_array_value_free_cb)(void *v);

struct c_array
{
    int len;
    int cap;
    void **array;
    c_array_value_free_cb free_cb;
};

typedef struct c_array Array;

#define FOR_ARRAY_EACH(array, block)     \
    {                                    \
        size_t i;                        \
        for (i = 0; i < array->len; i++) \
        {                                \
            void *v = array->array[i];   \
            block;                       \
        }                                \
    }

int array_init(Array *array);
void array_free(Array *array);

int array_add(Array *array, void *value);
int array_insert(Array *array, int index, void *value);
void *array_get(Array *array, int index);
void *array_get_first(Array *array);

int array_remove(Array *array, int index);
int array_clear(Array *array);
int array_remove_by_value(Array *array, void *value);

#endif