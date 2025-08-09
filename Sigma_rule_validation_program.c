#include <stdio.h>
#include <stdlib.h> // exit 위해 사용
#include <string.h> // string 관련 function
#include <yaml.h> // LibYAML

struct rule {
    char *name;
    char *status;
    char *description;
    char *references;
    char *author;
    char *date;
    char *modified;
    char *tags;
    struct logsource *logsource;
    struct detection *detection;
    char *condition;
    char *level;
};

struct logsource {
    char *product;
    char *category;
};

struct detection {
    char *selection;
    struct fields *fields;
    char *condition;
};

struct fields {
    char *name;
    char *appendix;
};

struct rule parse_rule() {
    struct rule r;
    

}


int main() {
    char fname[100];
    yaml_parser_t parser;
    yaml_event_t event;

    printf("SIGMA RULE NAME(.yaml): ");
    gets(fname);
    if(strstr(fname, ".yaml") == NULL) {
        fprintf(stderr, "Please Enter Valid Sigma Rule File\n");
        exit(1);        
    }
    FILE *input = fopen(fname, "rb");
    if(input == NULL) {
        fprintf(stderr, "No Selected File\n");
        exit(1);
    }

    yaml_parser_initialize(&parser);


    fclose(input);

    return 0;
}