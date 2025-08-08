#include <stdio.h>
#include <stdlib.h> // exit 위해 사용
#include <string.h> // string 관련 function

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
    FILE *fp = NULL;
    char fname[100];
    printf("SIGMA RULE NAME(.yaml): ");
    gets(fname);
    if(strchr(fname, '.yaml') == NULL) {
        fprintf(stderr, "Please Enter Valid Sigma Rule File\n");
        exit(1);        
    }
    fopen(fname, "r");
    if(fp == NULL) {
        fprintf(stderr, "No Selected File\n");
        exit(1);
    }


    fclose(fp);

    return 0;
}