#include "nfc.h"

static nfc_device *pnd;
static nfc_target nt;
static mifare_param mp;
static mifareul_32 mtDump;   // use the largest tag type for internal storage
static uint32_t uiBlocks = 0x20;
static uint32_t uiReadPages = 0;
static uint8_t iPWD[4] = { 0x0 };
static uint8_t iPACK[2] = { 0x0 };
static uint8_t iEV1Type = EV1_NONE;

// special unlock command
uint8_t  abtUnlock1[1] = { 0x40 };
uint8_t  abtUnlock2[1] = { 0x43 };

// EV1 commands
uint8_t  abtEV1[3] = { 0x60, 0x00, 0x00 };
uint8_t  abtPWAuth[7] = { 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

//Halt command
uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;
static int szRx;

static const nfc_modulation nmMifare = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
};

static void print_success_or_failure(bool bFailure, uint32_t *uiOkCounter, uint32_t *uiFailedCounter)
{
    printf("%c", (bFailure) ? 'f' : '.');
    if (uiOkCounter)
        *uiOkCounter += (bFailure) ? 0 : 1;
    if (uiFailedCounter)
        *uiFailedCounter += (bFailure) ? 1 : 0;
}

static  bool read_card(void)
{
    uint32_t page;
    bool    bFailure = false;
    uint32_t uiFailedPages = 0;

    printf("Reading %d pages |", uiBlocks);

    for (page = 0; page < uiBlocks; page += 4) {
        // Try to read out the data block
        if(nfc_initiator_mifare_cmd(pnd, MC_READ, page, &mp)) {
            memcpy(mtDump.amb[page / 4].mbd.abtData, mp.mpd.abtData, uiBlocks - page < 4 ? (uiBlocks - page) * 4 : 16);
        } else {
            bFailure = true;
        }
        for (uint8_t i = 0; i < (uiBlocks - page < 4 ? uiBlocks - page : 4); i++) {
            print_success_or_failure(bFailure, &uiReadPages, &uiFailedPages);
        }
    }
    printf("|\n");
    printf("Done, %d of %d pages read (%d pages failed).\n", uiReadPages, uiBlocks, uiFailedPages);
    fflush(stdout);

    // copy EV1 secrets to dump data
    switch(iEV1Type) {
    case EV1_UL11:
        memcpy(mtDump.amb[4].mbc11.pwd, iPWD, 4);
        memcpy(mtDump.amb[4].mbc11.pack, iPACK, 2);
        break;
    case EV1_UL21:
        memcpy(mtDump.amb[9].mbc21a.pwd, iPWD, 4);
        memcpy(mtDump.amb[9].mbc21b.pack, iPACK, 2);
        break;
    case EV1_NONE:
    default:
        break;
    }

    return (!bFailure);
}

static  bool transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
{
    // Transmit the bit frame command, we don't use the arbitrary parity feature
    if((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
      return false;

    return true;
}


static  bool transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
    if ((szRx = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
        return false;

    return true;
}

static bool raw_mode_start(void)
{
    // Configure the CRC
    if(nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
        nfc_perror(pnd, "nfc_configure");
        return false;
    }
    // Use raw send/receive methods
    if(nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
        nfc_perror(pnd, "nfc_configure");
        return false;
    }
    return true;
}

static bool raw_mode_end(void)
{
    // reset reader
    // Configure the CRC
    if(nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, true) < 0) {
        nfc_perror(pnd, "nfc_device_set_property_bool");
        return false;
    }
    // Switch off raw send/receive methods
    if(nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true) < 0) {
        nfc_perror(pnd, "nfc_device_set_property_bool");
        return false;
    }
    return true;
}

static bool get_ev1_version(void)
{
    if (!raw_mode_start())
        return false;
    iso14443a_crc_append(abtEV1, 1);
    if (!transmit_bytes(abtEV1, 3)) {
        raw_mode_end();
        return false;
    }
    if (!raw_mode_end())
        return false;
    if (!szRx)
        return false;
    return true;
}

static bool ev1_load_pwd(uint8_t target[4], const char *pwd)
{
    unsigned int tmp[4];
    if (sscanf(pwd, "%2x%2x%2x%2x", &tmp[0], &tmp[1], &tmp[2], &tmp[3]) != 4)
        return false;
    target[0] = tmp[0];
    target[1] = tmp[1];
    target[2] = tmp[2];
    target[3] = tmp[3];
    return true;
}

static bool ev1_pwd_auth(uint8_t *pwd)
{
    if (!raw_mode_start())
        return false;
    memcpy(&abtPWAuth[1], pwd, 4);
    iso14443a_crc_append(abtPWAuth, 5);
    if (!transmit_bytes(abtPWAuth, 7))
        return false;
    if (!raw_mode_end())
        return false;
    return true;
}

static bool unlock_card(void)
{
    if (!raw_mode_start())
        return false;
    iso14443a_crc_append(abtHalt, 2);
    transmit_bytes(abtHalt, 4);
    // now send unlock
    if(!transmit_bits(abtUnlock1, 7)) {
        return false;
    }
    if (!transmit_bytes(abtUnlock2, 1)) {
        return false;
    }

    if (!raw_mode_end())
        return false;
    return true;
}

static bool check_magic()
{
    bool     bFailure = false;
    int      uid_data;

    for (uint32_t page = 0; page <= 1; page++) {
        // Show if the readout went well
        if(bFailure) {
            // When a failure occured we need to redo the anti-collision
            if(nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
                ERR("tag was removed");
                return false;
            }
            bFailure = false;
        }

        uid_data = 0x00000000;

        memcpy(mp.mpd.abtData, &uid_data, sizeof uid_data);
        memset(mp.mpd.abtData + 4, 0, 12);

        //Force the write without checking for errors - otherwise the writes to the sector 0 seem to complain
        nfc_initiator_mifare_cmd(pnd, MC_WRITE, page, &mp);
    }

    //Check that the ID is now set to 0x000000000000
    if(nfc_initiator_mifare_cmd(pnd, MC_READ, 0, &mp)) {
        //printf("%u", mp.mpd.abtData);
        bool result = true;
        for (int i = 0; i <= 7; i++) {
            if (mp.mpd.abtData[i] != 0x00) result = false;
        }

        if (result) {
            return true;
        }

    }

    //Initially check if we can unlock via the MF method
    if(unlock_card()) {
        return true;
    } else {
        return false;
    }

}

static  bool write_card(bool write_otp, bool write_lock, bool write_uid)
{
    uint32_t uiBlock = 0;
    bool    bFailure = false;
    uint32_t uiWrittenPages = 0;
    uint32_t uiSkippedPages = 0;
    uint32_t uiFailedPages = 0;

    char    buffer[BUFSIZ];

    write_otp =  false;
    write_lock = false;
    write_uid = false;

    printf("Writing %d pages |", uiBlocks);
    /* We may need to skip 2 first pages. */
    if (!write_uid) {
        printf("ss");
        uiSkippedPages = 2;
    }
    else {
        if (!check_magic()) {
            printf("\nUnable to unlock card - are you sure the card is magic?\n");
            return false;
        }
    }

    for (uint32_t page = uiSkippedPages; page < uiBlocks; page++) {
        if ((page == 0x2) && (!write_lock)) {
            printf("s");
            uiSkippedPages++;
            continue;
        }
        if ((page == 0x3) && (!write_otp)) {
            printf("s");
            uiSkippedPages++;
            continue;
        }
        // Check if the previous readout went well
        if(bFailure) {
            // When a failure occured we need to redo the anti-collision
            if(nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
                ERR("tag was removed");
                return false;
            }
            bFailure = false;
        }
        // For the Mifare Ultralight, this write command can be used
        // in compatibility mode, which only actually writes the first
        // page (4 bytes). The Ultralight-specific Write command only
        // writes one page at a time.
        uiBlock = page / 4;
        memcpy(mp.mpd.abtData, mtDump.amb[uiBlock].mbd.abtData + ((page % 4) * 4), 4);
        memset(mp.mpd.abtData + 4, 0, uiBlocks - uiSkippedPages);
        if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, page, &mp))
            bFailure = true;
        print_success_or_failure(bFailure, &uiWrittenPages, &uiFailedPages);
    }
    printf("|\n");
    printf("Done, %d of %d pages written (%d pages skipped, %d pages failed).\n", uiWrittenPages, uiBlocks, uiSkippedPages, uiFailedPages);

    return true;
}

static int list_passive_targets(nfc_device *_pnd)
{
    int res = 0;

    nfc_target ant[MAX_TARGET_COUNT];

    if (nfc_initiator_init(_pnd) < 0) {
        return -EXIT_FAILURE;
    }

    if ((res = nfc_initiator_list_passive_targets(_pnd, nmMifare, ant, MAX_TARGET_COUNT)) >= 0) {
        int i;

        if (res > 0)
            printf("%d ISO14443A passive target(s) found:\n", res);

        for (i = 0; i < res; i++) {
            size_t  szPos;

            printf("\t");
            for (szPos = 0; szPos < ant[i].nti.nai.szUidLen; szPos++) {
                printf("%02x", ant[i].nti.nai.abtUid[szPos]);
            }
            printf("\n");
        }

    }

    return 0;
}

static size_t str_to_uid(const char *str, uint8_t *uid)
{
    uint8_t i;

    memset(uid, 0x0, MAX_UID_LEN);
    i = 0;
    while ((*str != '\0') && ((i >> 1) < MAX_UID_LEN)) {
        char nibble[2] = { 0x00, '\n' }; /* for strtol */

        nibble[0] = *str++;
        if (isxdigit(nibble[0])) {
            if (isupper(nibble[0]))
                nibble[0] = tolower(nibble[0]);
            uid[i >> 1] |= strtol(nibble, NULL, 16) << ((i % 2) ? 0 : 4) & ((i % 2) ? 0x0f : 0xf0);
            i++;
        }
    }
    return i >> 1;
}

game readGame()
{
    uint8_t iUID[MAX_UID_LEN] = { 0x0 };
    size_t  szUID = 0;
    bool    bOTP = false;
    bool    bLock = false;
    bool    bUID = false;
    FILE   *pfDump;

    char fileName[] = "dump.mfd";

    nfc_context *context;
    nfc_init(&context);
    if (context == NULL) {
        ERR("Unable to init libnfc (malloc)");
        exit(EXIT_FAILURE);
    }

    // Try to open the NFC device
    pnd = nfc_open(context, NULL);
    if (pnd == NULL) {
        ERR("Error opening NFC device");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    printf("NFC device: %s opened\n", nfc_device_get_name(pnd));

    if (list_passive_targets(pnd)) {
        nfc_perror(pnd, "nfc_device_set_property_bool");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Let the device only try once to find a tag
    if(nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
        nfc_perror(pnd, "nfc_device_set_property_bool");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Try to find a MIFARE Ultralight tag
    if(nfc_initiator_select_passive_target(pnd, nmMifare, (szUID) ? iUID : NULL, szUID, &nt) <= 0) {
        ERR("no tag was found\n");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Test if we are dealing with a MIFARE compatible tag
    if(nt.nti.nai.abtAtqa[1] != 0x44) {
        ERR("tag is not a MIFARE Ultralight card\n");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    // Get the info from the current tag
    printf("Using MIFARE Ultralight card with UID: ");
    size_t  szPos;
    for (szPos = 0; szPos < nt.nti.nai.szUidLen; szPos++) {
        printf("%02x", nt.nti.nai.abtUid[szPos]);
    }
    printf("\n");

    bool bRF = read_card();

    printf("Writing data to file: %s ... ", fileName);
    fflush(stdout);
    pfDump = fopen(fileName, "wb");
    if (pfDump == NULL) {
        printf("Could not open file: %s\n", fileName);
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    if (fwrite(&mtDump, 1, uiReadPages * 4, pfDump) != uiReadPages * 4) {
        printf("Could not write to file: %s\n", fileName);
        fclose(pfDump);
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    fclose(pfDump);
    printf("Done.\n");


    game temp;

    temp.gametype = (ENUM_GAMETYPE) mtDump.amb[1].mbd.abtData[0];

    switch((ENUM_GAMETYPE)mtDump.amb[1].mbd.abtData[0])
    {
        case NES:
            temp.gametype = "nes";
            break;
        case SNES:
            temp.gametype = "snes";
        case GB:
            temp.gametype = "GB";
            break;
        case GBC:
            temp.gametype = "GBC";
            break;
        case GBA:
            temp.gametype = "GBA";
            break;
        case GENESIS:
            temp.gametype = "genesis";
            break;
    }

    for (int i = 0; i <= mtDump.amb[2].mbd.abtData[0] / 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            if (mtDump.amb[i + 3].mbd.abtData[j] != 0)
            {
                temp.filename += mtDump.amb[i + 3].mbd.abtData[j];
            }
            else
                break;
        }
    }

    nfc_close(pnd);
    nfc_exit(context);

    return temp;
}


bool writeGame(game out)
{

    uint8_t iUID[MAX_UID_LEN] = { 0x0 };
    size_t  szUID = 0;
    bool    bOTP = false;
    bool    bLock = false;
    bool    bUID = false;
    FILE   *pfDump;

    nfc_context *context;
    nfc_init(&context);
    if (context == NULL) {
        ERR("Unable to init libnfc (malloc)");
        exit(EXIT_FAILURE);
    }

    // Try to open the NFC device
    pnd = nfc_open(context, NULL);
    if (pnd == NULL) {
        ERR("Error opening NFC device");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    printf("NFC device: %s opened\n", nfc_device_get_name(pnd));

    if (list_passive_targets(pnd)) {
        nfc_perror(pnd, "nfc_device_set_property_bool");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Let the device only try once to find a tag
    if(nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
        nfc_perror(pnd, "nfc_device_set_property_bool");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Try to find a MIFARE Ultralight tag
    if(nfc_initiator_select_passive_target(pnd, nmMifare, (szUID) ? iUID : NULL, szUID, &nt) <= 0) {
        ERR("no tag was found\n");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    // Test if we are dealing with a MIFARE compatible tag
    if(nt.nti.nai.abtAtqa[1] != 0x44) {
        ERR("tag is not a MIFARE Ultralight card\n");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    // Get the info from the current tag
    printf("Using MIFARE Ultralight card with UID: ");
    size_t  szPos;
    for (szPos = 0; szPos < nt.nti.nai.szUidLen; szPos++) {
        printf("%02x", nt.nti.nai.abtUid[szPos]);
    }
    printf("\n");

    bool bRF = read_card();

    for (int i = 1; i < uiBlocks; i++)
    {
        for (int j = 0; j < 16; j++)
            mtDump.amb[i].mbd.abtData[j] = 0;
    }

    if(out.gametype == "nes")
        mtDump.amb[1].mbd.abtData[0] = NES;
    else if(out.gametype == "snes")
        mtDump.amb[1].mbd.abtData[0] = SNES;
    else if(out.gametype == "gb")
        mtDump.amb[1].mbd.abtData[0] = GB;
    else if(out.gametype == "gbc")
        mtDump.amb[1].mbd.abtData[0] = GBC;
    else if(out.gametype == "gba")
        mtDump.amb[1].mbd.abtData[0] = GBA;
    else if(out.gametype == "genesis" || out.gametype == "megadrive")
        mtDump.amb[1].mbd.abtData[0] = GENESIS;

    std::string temp = out.filename;

    mtDump.amb[2].mbd.abtData[0] = out.filename.length();

    for (int i = 0; i <= out.filename.length() / 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            if (temp.length() != 0)
            {
                mtDump.amb[i + 3].mbd.abtData[j] = temp.at(0);
                temp.erase(0, 1);
            }
            else
                break;
        }
    }
    return write_card(bOTP, bLock, bUID);
}
