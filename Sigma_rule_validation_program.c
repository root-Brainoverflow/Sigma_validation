#include <stdio.h>
#include <stdlib.h> // exit 위해 사용
#include <string.h> // string 관련 function
#include <yaml.h>   // LibYAML
#include <ctype.h>

typedef struct Tags{ char tags[20]; }Tags;

typedef struct Details{ char body[80]; }Details;

typedef struct Selection {
    char name[80];
    char field[80];
    Details details[80];
}Selection;

typedef struct Logsource {
    char product[80];
    char category[80];
}Logsource;

typedef struct Detection {
    Selection selection[80];
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
    Logsource logsource[1];
    Detection detection[1];
    char level[80];
    Tags tags[20];
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
    int selection = 0;
    int details = 0;
    int in_detection = 0;
    int in_tag = 0;

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
            is_mapping++;
        }

        if (event.type == YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
            break;
        }

        if (event.type == YAML_MAPPING_END_EVENT || event.type == YAML_SEQUENCE_END_EVENT) {
            if (in_detection == 1) {
                is_mapping--;
                continue;
            }
            is_key = 0;
            is_mapping = 0;
        }

        if (event.type == YAML_SEQUENCE_START_EVENT) {
            is_mapping++;
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
                    strncpy(rule->logsource->product, val, sizeof(rule->logsource->product) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "category") == 0) {
                    strncpy(rule->logsource->category, val, sizeof(rule->logsource->category) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "detection") == 0)  {
                    strncpy(key, (char *)event.data.scalar.value, sizeof(key) - 1);
                    in_detection = 1;
                }
                else if (is_mapping == 2) {
                    strncpy(rule->detection->selection[selection].name, key, sizeof(rule->detection->selection[selection].name) - 1 );
                    strncpy(rule->detection->selection[selection].field, val, sizeof(rule->detection->selection[selection].field) - 1);
                    selection++;
                    is_key = 0;
                }
                else if (is_mapping >= 3) {
                    selection--;
                    strncpy(rule->detection->selection[selection].details[details].body, key, sizeof(rule->detection->selection[selection].details[details].body) - 1);
                    details++;
                    strncpy(rule->detection->selection[selection].details[details].body, val, sizeof(rule->detection->selection[selection].details[details].body) - 1);
                    is_key = 0;
                    details = 0;
                    selection ++;
                }
                else if (strcmp(key, "condition") == 0) {
                    strncpy(rule->detection->condition, val, sizeof(rule->detection->condition) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "level") == 0) {
                    strncpy(rule->level, val, sizeof(rule->level) - 1);
                    is_key = 0;
                }
                else if (strcmp(key, "tags") == 0) {
                    strncpy(rule->tags[in_tag].tags, val, sizeof(rule->tags[in_tag].tags) - 1);
                    in_tag++;
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
    printf("description: %s", rule->description);
    printf("author: %s\n", rule->author);
    printf("date: %s\n", rule->date);
    if(rule->modified[0] != '\0')
        printf("modified: %s\n", rule->modified);
    printf("references:\n %s\n\n", rule->references);
    printf("logsource:\n");
    printf("    product: %s\n", rule->logsource->product);
    printf("    category: %s\n\n", rule->logsource->category);
    printf("detection:\n");
    for (int i = 0; rule->detection->selection[i].name[0] != '\0'; i++){
        printf("    %s\n", rule->detection->selection[i].name);
        printf("        %s\n", rule->detection->selection[i].field);
        for (int j = 0; rule->detection->selection[i].details[j].body[0] != '\0'; j++)
            printf("            - %s\n", rule->detection->selection[i].details[j].body);
    }
    printf("    condition: %s\n\n", rule->detection->condition);
    printf("level: %s\n", rule->level);
    printf("tags: \n");
    for (int i = 0; rule->tags[i].tags[0] != '\0';i++)
        printf("     - %s\n", rule->tags[i].tags);
    printf("\n");
}

void validate_yamllint(const char *filename){
    printf("----------- YAMLlint VALIDATION -----------\n\n");
    char command[256] = "yamllint ";
    strcat(command, filename);
    printf("----------------- RESULT ----------------- \n\n");
    int result = system(command);
    if (result != 0){
        printf("ERROR: YAMLlint Failed\n\n");
        exit(1);
    }
    printf("------------------------------------------\n\n");

}

void validate_logsource(const char *logsource){
    char *category[] = {"process_creation", "process_access", "network_connection", "driver_load",
    "image_load", "file_event", "file_delete", "registry_event", "registry_add", "registry_delete",
    "registry_set", "create_stream_hash", "dns_query"};
    int count = sizeof(category) / sizeof(category[0]);
    for (int i = 0; i < count; i++){
        if(strcmp(logsource, category[i]) == 0) {
            printf("[PASS] VALID SIGMA LOGSOURCE\n");
            return;
        }
    }
    printf("[ERROR] INVALID LOGSOURCE -> The provided category is not valid\n");
}

void validate_date(const char *date){
    for (int i = 0; i < strlen(date); i++){
        char a = date[i];
        if (i == 4 || i == 7) {
            if (a == '/') {
                printf("[ERROR] INVALID DATE -> The date should use hyphens('-'), not slashes('/')\n");
                return;
            } if (a != '-') {
                printf("[ERROR] INVALID DATE -> The date should be formatted as YYYY-MM-DD\n");
                return;
            }
        }
    }
    printf("[PASS] VALID SIGMA DATE\n");
}

void validate_status(const char *status){
    int is_valid = 0;
    char *valid_status[] = {"stable", "test", "experimental", "deprecated", "unsupported"};
    size_t count = sizeof(valid_status) / sizeof(valid_status[0]);
    if (status == NULL) {
        printf("[ERROR] INVALID STATUS -> Status is NULL\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        if (strcmp(status, valid_status[i]) == 0) {
            is_valid = 1;
            break;
        }
    }
    if (is_valid == 1) {
        printf("[PASS] VALID SIGMA STATUS\n");
    } else {
        printf("[ERROR] Not a valid status name\n");
    }

}

void validate_uuid(const char *id) {
    int is_valid = 1;
    if(id == NULL) {
        printf("[ERROR] INVALID UUID -> UUID is EMPTY\n");
        return;
    }
    if (strlen(id) != 36) {
        printf("[ERROR] INVALID UUID -> A UUID must have a total length of 36 characters\n");
        is_valid = 0;
    }
    for (int i = 0; i < 36; i++){
        char a = id[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (a != '-'){
                printf("[ERROR] INVALID UUID -> Incorrect hyphen position\n");
                is_valid = 0;
                break;
            }
        }
        else {
            if (!isxdigit(a)) {
            printf("[ERROR] INVALID UUID -> Invalid hexadecimal character\n");
            is_valid = 0;
            break;
            }
        }
    }
    if (is_valid == 1) {printf("[PASS] VALID SIGMA ID\n");}
}

void validate_sigma(const Rule *rule){
    validate_uuid(rule->id);
    validate_status(rule->status);
    validate_date(rule->date);
    validate_logsource(rule->logsource->category);
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

    validate_yamllint(fname);
    parse_yaml(fname, &rule);
    print_yaml(&rule);
    validate_sigma(&rule);
    return 0;
}