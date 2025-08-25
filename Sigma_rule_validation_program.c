#include <stdio.h>
#include <stdlib.h> // exit 위해 사용
#include <string.h> // string 관련 function
#include <yaml.h>   // LibYAML

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
    if (!file) {
        fprintf(stderr, "No Selected File\n");
        exit(1);
    }

    yaml_parser_t parser;
    yaml_event_t event;
    char key[80] = {0};
    int is_key = 0;
    int is_mapping = 0;

    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize YAML parser\n");
        fclose(file);
        exit(1);
    }
    yaml_parser_set_input_file(&parser, file);

    while (1) {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "YAML parse error\n");
            yaml_parser_delete(&parser);
            fclose(file);
            exit(1);
        }

        if (event.type == YAML_MAPPING_START_EVENT) {
            is_mapping += 1;
        }

        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            break;
        }

        if (event.type == YAML_MAPPING_END_EVENT || event.type == YAML_SEQUENCE_END_EVENT) {
            is_key = 0;
            is_mapping = 0;
        }

        if (event.type == YAML_SCALAR_EVENT) {
            if (!is_key) {
                strncpy(key, (char *)event.data.scalar.value, sizeof(key) - 1);
                key[sizeof(key) - 1] = '\0';
                is_key = 1;
            } else {
                const char *val = (char *)event.data.scalar.value;

                if (strcmp(key, "title") == 0) {
                    strncpy(rule->title, val, sizeof(rule->title) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "id") == 0) {
                    strncpy(rule->id, val, sizeof(rule->id) - 1);
                    is_key = 0;
                }  
                else if (strcmp(key, "status") == 0) {
                    strncpy(rule->status, val, sizeof(rule->status) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "description") == 0) {
                    strncpy(rule->description, val, sizeof(rule->description) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "references") == 0) {
                    strncpy(rule->references, val, sizeof(rule->references) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "author") == 0) {
                    strncpy(rule->author, val, sizeof(rule->author) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "date") == 0) {
                    strncpy(rule->date, val, sizeof(rule->date) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "modified") == 0) {
                    strncpy(rule->modified, val, sizeof(rule->modified) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "logsource") == 0) 
                    strncpy(key, (char *)event.data.scalar.value, sizeof(key) - 1);
                else if (strcmp(key, "product") == 0) {
                    strncpy(rule->logsource[0].product, val, sizeof(rule->logsource[0].product) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "category") == 0) {
                    strncpy(rule->logsource[0].category, val, sizeof(rule->logsource[0].category) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "detection") == 0) 
                    strncpy(key, (char *)event.data.scalar.value, sizeof(key) - 1);
                else if (strcmp(key, "selection") == 0) {
                    strncpy(rule->detection[0].selection, val, sizeof(rule->detection[0].selection) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "condition") == 0) {
                    strncpy(rule->detection[0].condition, val, sizeof(rule->detection[0].condition) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "level") == 0) {
                    strncpy(rule->level, val, sizeof(rule->level) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "tags") == 0) {
                    strncpy(rule->tags, val, sizeof(rule->tags) - 1);
                    is_key = 0;
                }
            }
        }

        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(file);
}

void print_yaml(const Rule *rule) {
    printf("title: %s\n", rule->title);
    printf("id: %s\n", rule->id);
    printf("status: %s\n", rule->status);
    printf("description: %s\n", rule->description);
    printf("author: %s\n", rule->author);
    printf("date: %s\n\n", rule->date);
    if(rule->modified[0] != '\0')
        printf("modified: %s\n\n", rule->modified);
    printf("references:\n %s\n", rule->references);
    printf("logsource:\n");
    printf("    product: %s\n", rule->logsource[0].product);
    printf("    category: %s\n", rule->logsource[0].category);
    printf("detection:\n");
    printf("    selection:\n %s\n", rule->detection[0].selection);
    printf("    condition:\n %s\n", rule->detection[0].condition);
    printf("level: %s\n", rule->level);
    printf("tags:\n %s\n", rule->tags);
}

int main() {
    char fname[256];
    Rule rule;
    memset(&rule, 0, sizeof(rule));

    printf("SIGMA RULE NAME(.yaml): ");
    if (!fgets(fname, sizeof(fname), stdin)) {
        fprintf(stderr, "Failed to read filename\n");
        exit(1);
    }

    size_t len = strlen(fname);
    if (len > 0 && fname[len - 1] == '\n')
        fname[len - 1] = '\0';
    if (fname[0] == '\0') {
        fprintf(stderr, "Filename is empty\n");
        exit(1);
    }

    if (strstr(fname, ".yaml") == NULL) {
        fprintf(stderr, "Please Enter Valid Sigma Rule File\n");
        exit(1);
    }

    parse_yaml(fname, &rule);
    print_yaml(&rule);
    return 0;
}