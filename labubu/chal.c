#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define MAX_LABUBU 0x10
#define LABUBU_SIZE 0x400

char *labubu_holder[MAX_LABUBU] = {0};

int get_int() {
  printf("> ");
  char n[0x10];
  fgets(n, sizeof(n), stdin);
  return atoi(n);
}

void make_labubu() {
  printf("idx?: ");
  int idx = get_int();
  if (idx >= MAX_LABUBU || idx < 0) {
    exit(1);
  }
  labubu_holder[idx] = malloc(LABUBU_SIZE);
  printf("Your labubu has been bought!\n");
}

void sell_labubu() {
  printf("Which labubu to sell...\n");
  int idx = get_int();
  if (idx >= MAX_LABUBU || idx < 0) {
    exit(1);
  }
  free(labubu_holder[idx]);
  printf("You monster...\n");
}

void name_labubu() {
  printf("Which labubu to name: \n");
  int idx = get_int();
  if (idx >= MAX_LABUBU || idx < 0) {
    exit(1);
  }
  if (labubu_holder[idx] == NULL) {
    printf("There is no labubu there...\n");
    exit(1);
  }
  printf("Name your labubu\n");
  fgets(labubu_holder[idx], LABUBU_SIZE, stdin);
  printf("Your labubu has been named %s\n", labubu_holder[idx]);
}

void admire_labubu() {
  printf("Which limited edition 24k gold matcha performative labubu do you "
         "want to admire?\n");
  int idx = get_int();
  if (idx >= MAX_LABUBU || idx < 0) {
    exit(1);
  }
  if (labubu_holder[idx] == NULL) {
    printf("There is no labubu there...\n");
    exit(1);
  }
  write(1, labubu_holder[idx], LABUBU_SIZE);
}

int menu() {
  puts("Welcome to the place of labubu");
  puts("1: Buy a labubu");
  puts("2: Name a labubu");
  puts("3: Admire an labubu");
  puts("4: Sell a Labubu???");
  puts("5: Abandon your Labubu...");
  return get_int();
}

void setup() {
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
}

int main() {
  setup();
  while (1) {
    switch (menu()) {
    case 1:
      make_labubu();
      break;
    case 2:
      name_labubu();
      break;
    case 3:
      admire_labubu();
      break;
    case 4:
      sell_labubu();
      break;
    default:
      exit(0);
      break;
    }
  }
}
