#include <stdio.h>
#include <stdlib.h> // exit 위해 사용
#include <string.h> // string 관련 function
#include <yaml.h> // LibYAML

typedef struct Logsource {
    char product[80];
    char category[80];
}Logsource;

typedef struct Detection {
    char selection[80];
    char condition[80];
}Detection;

typedef struct Rule {
    char title[80];
    char id[80];
    char status[80];
    char description[200];
    char references[80];
    char author[80];
    char date[80];
    char modified[80];
    Logsource logsource[80];
    Detection detection[80];
    char level[80];
    char tags[80];
}Rule;

void parse_yaml(const char *filename, Rule *rule) {
    FILE *file = fopen(filename, "r");
    if(!file) {
        fprintf(stderr, "No Selected File\n");
        exit(1);
    }

    yaml_parser_t parser;
    yaml_event_t event;
    char key[20] = {0};
    int is_key = 0;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, file);

    while(1) {
        yaml_parser_parse(&parser, &event);
        if (event.type == YAML_STREAM_END_EVENT)
            break;

        if (event.type == YAML_SCALAR_EVENT) {
            if (!is_key){
                strncpy(key, (char *)event.data.scalar.value, sizeof(key) - 1);
                is_key = 1;
            } else {
                if (strcmp(key, "title") == 0)
                    strncpy(rule->title, (char *)event.data.scalar.value, sizeof(rule->title) - 1);
                else if (strcmp(key, "id") == 0)
                    strncpy(rule->id, (char *)event.data.scalar.value, sizeof(rule->id) - 1);
                else if (strcmp(key, "status") == 0)
                    strncpy(rule->status, (char *)event.data.scalar.value, sizeof(rule->status) - 1);
                else if (strcmp(key, "description") == 0)
                    strncpy(rule->description, (char *)event.data.scalar.value, sizeof(rule->description) - 1);
                else if (strcmp(key, "references") == 0)
                    strncpy(rule->references, (char *)event.data.scalar.value, sizeof(rule->references) - 1);
                else if (strcmp(key, "author") == 0)
                    strncpy(rule->author, (char *)event.data.scalar.value, sizeof(rule->author) - 1);
                else if (strcmp(key, "date") == 0)
                    strncpy(rule->date, (char *)event.data.scalar.value, sizeof(rule->date) - 1);
                else if (strcmp(key, "modified") == 0)
                    strncpy(rule->modified, (char *)event.data.scalar.value, sizeof(rule->modified) - 1);
                else if (strcmp(key, "logsource") == 0) {
                    strncpy(key, (char *)event.data.scalar.value, sizeof(key) - 1);
                    continue;
                }
                else if (strcmp(key, "product") == 0)
                    strncpy(rule->logsource->product, (char *)event.data.scalar.value, sizeof(rule->logsource->product) - 1);
                else if (strcmp(key, "category") == 0)
                    strncpy(rule->logsource->category, (char *)event.data.scalar.value, sizeof(rule->logsource->category) - 1);
                else if (strcmp(key, "selection") == 0)
                    strncpy(rule->detection->selection, (char *)event.data.scalar.value, sizeof(rule->detection->selection) - 1);
                else if (strcmp(key, "condition") == 0)
                    strncpy(rule->detection->condition, (char *)event.data.scalar.value, sizeof(rule->detection->condition) - 1);
                else if (strcmp(key, "level") == 0)
                    strncpy(rule->level, (char *)event.data.scalar.value, sizeof(rule->level) - 1);
                else if (strcmp(key, "tags") == 0)
                    strncpy(rule->tags, (char *)event.data.scalar.value, sizeof(rule->tags) - 1);

                is_key = 0;
            }
        }

        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(file);
}

void print_yaml(const Rule *rule){
    printf("title: %s\n", rule->title);
    printf("id: %s\n", rule->id);
    printf("status: %s\n", rule->status);
    printf("description: %s\n", rule->description);
    printf("author: %s\n", rule->author);
    printf("date: %s\n", rule->date);
    printf("references:\n %s\n", rule->references);
    printf("logsource:\n");
    printf("    product: %s\n", rule->logsource->product);
    printf("    category: %s\n", rule->logsource->category);
    printf("detection:\n");
    printf("    selection:\n %s\n", rule->detection->selection);
    printf("    condition:\n %s\n", rule->detection->condition);
    printf("level:\n %s\n", rule->level);
    printf("tags:\n %s\n", rule->tags);
}


int main() {
    char fname[30];
    Rule rule = {0};
    printf("SIGMA RULE NAME(.yaml): ");
    gets(fname);
    if(strstr(fname, ".yaml") == NULL) {
        fprintf(stderr, "Please Enter Valid Sigma Rule File\n");
        exit(1);        
    }
    parse_yaml(fname, &rule);
    print_yaml(&rule);

    return 0;
}