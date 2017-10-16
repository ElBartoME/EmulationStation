extern "C"
{

#include <nfc/nfc.h>

#include "nfc-utils.h"
#include "mifare.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <iostream>

#include <string.h>
#include <ctype.h>

#define MAX_TARGET_COUNT 16
#define MAX_UID_LEN 10

#define EV1_NONE 0
#define EV1_UL11 1
#define EV1_UL21 2

typedef struct {
    mifareul_block amb[32];
} mifareul_32;

typedef enum
{
    UNDEFINED,
    NES,
    SNES,
    GB,
    GBC,
    GBA,
    GENESIS
} ENUM_GAMETYPE;

typedef struct
{
    std::string gametype;
    std::string filename;
} game;

static void print_success_or_failure(bool bFailure, uint32_t *uiCounter);
static  bool read_card(void);

game readGame();
bool writeGame(game out);
