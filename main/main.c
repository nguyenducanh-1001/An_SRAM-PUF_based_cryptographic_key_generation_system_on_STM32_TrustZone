#include "main.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PUF_BASE_ADDR    ((volatile uint32_t *)0x30000000U)
#define PUF_WORDS        64U
#define PUF_TOTAL_BITS   (PUF_WORDS * 32U)
#define KEY_BITS         128
#define WEIGHT_THRESH    4

#define VTOR_TABLE_NS_START_ADDR  0x08100000UL

UART_HandleTypeDef huart1;

static uint32_t puf_raw[PUF_WORDS];

static uint8_t  weight[PUF_TOTAL_BITS];
static uint16_t mask[KEY_BITS];

static uint8_t  Y[KEY_BITS / 8];
static uint8_t  C[KEY_BITS / 8];
static uint8_t  W[KEY_BITS / 8];
static uint8_t  Syn;
static uint8_t  Key[32];

static void NonSecure_Init(void);
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_GTZC_S_Init(void);
static void MX_USART1_UART_Init(void);
static void SHA256(const uint8_t *msg, uint32_t len, uint8_t digest[32]);

int __io_putchar(int ch)
{
    HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, HAL_MAX_DELAY);
    return ch;
}

static void PrintHex(const char *label, const uint8_t *buf, uint32_t len)
{
    printf("\r\n=== %s ===\r\n", label);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i & 15) == 15) printf("\r\n");
    }
    printf("\r\n");
}

// Read Raw Sram
static void PUF_CaptureRaw(void)
{
    for (uint32_t i = 0; i < PUF_WORDS; i++)
        puf_raw[i] = PUF_BASE_ADDR[i];
}

static inline uint8_t PUF_GetRawBit(uint32_t idx)
{
    return (uint8_t)((puf_raw[idx / 32] >> (idx % 32)) & 1u);
}

// Calculate weight
static void PUF_ComputeWeights(void)
{
    memset(weight, 0, sizeof(weight));

    static uint16_t stable_pos[PUF_TOTAL_BITS];
    uint32_t n_stable = 0;

    // run > 1, cho vào mảng
    uint32_t i = 0;
    while (i < PUF_TOTAL_BITS)
    {
        uint32_t run_end = i + 1;
        while (run_end < PUF_TOTAL_BITS &&
               PUF_GetRawBit(run_end) == PUF_GetRawBit(i))
            run_end++;

        if (run_end - i >= 2)
            for (uint32_t r = i; r < run_end; r++)
                stable_pos[n_stable++] = (uint16_t)r;

        i = run_end;
    }

    // gán weight
    for (uint32_t k = 0; k < n_stable; k++)
    {
        if (k == 0 || k == n_stable - 1) { weight[stable_pos[k]] = 1; continue; }

        uint8_t  w = 1;
        uint32_t j = 1;
        while (k >= j && (k + j) < n_stable)
        {
            if (stable_pos[k - j] != (uint16_t)(stable_pos[k] - j) ||
                stable_pos[k + j] != (uint16_t)(stable_pos[k] + j))
                break;
            w++;
            j++;
        }
        weight[stable_pos[k]] = (w > 255u) ? 255u : w;
    }
}

// Chọn 128 vị trí
static void PUF_SelectMask(void)
{
    static uint16_t cand_pos[PUF_TOTAL_BITS];
    static uint8_t  cand_w  [PUF_TOTAL_BITS];
    uint32_t n = 0;

    int thresh = WEIGHT_THRESH;
    while (thresh >= 1)
    {
        n = 0;
        for (uint32_t i = 0; i < PUF_TOTAL_BITS; i++)
            if (weight[i] >= (uint8_t)thresh)
                { cand_pos[n] = (uint16_t)i; cand_w[n] = weight[i]; n++; }
        if (n >= KEY_BITS) break;
        thresh--;
    }

    if (n < KEY_BITS) {
        for (uint32_t i = 0; i < KEY_BITS; i++) mask[i] = (uint16_t)i;
        return;
    }

    for (uint32_t k = 0; k < KEY_BITS; k++)
    {
        uint32_t best = k;
        for (uint32_t j = k + 1; j < n; j++)
            if (cand_w[j] > cand_w[best]) best = j;
        uint16_t tp = cand_pos[k]; cand_pos[k] = cand_pos[best]; cand_pos[best] = tp;
        uint8_t  tw = cand_w[k];   cand_w[k]   = cand_w[best];   cand_w[best]   = tw;
        mask[k] = cand_pos[k];
    }

    for (uint32_t i = 0; i < KEY_BITS - 1; i++)
        for (uint32_t j = i + 1; j < KEY_BITS; j++)
            if (mask[j] < mask[i]) { uint16_t t = mask[i]; mask[i] = mask[j]; mask[j] = t; }
}

// Lọc
static void PUF_ApplyMask(void)
{
    memset(Y, 0, sizeof(Y));
    for (uint32_t i = 0; i < KEY_BITS; i++)
        if (PUF_GetRawBit(mask[i]))
            Y[i / 8] |= (uint8_t)(1u << (i % 8));
}

// RNG
static uint8_t  rng_pool[32];
static uint32_t rng_pool_used = 0;
static uint32_t lfsr_state;

static uint32_t LFSR_Next(void)
{
    uint32_t lsb = lfsr_state & 1u;
    lfsr_state >>= 1;
    if (lsb) lfsr_state ^= 0xB4BCD35Cu;
    return lfsr_state;
}

static void RNG_Init(void)
{
    static uint8_t entropy_buf[256];
    uint32_t n_bytes = 0;
    uint8_t  cur = 0, bit_pos = 0;

    for (uint32_t i = 0; i < PUF_TOTAL_BITS; i++)
    {
        if (weight[i] == 1) {
            if (PUF_GetRawBit(i)) cur |= (uint8_t)(1u << bit_pos);
            if (++bit_pos == 8) {
                entropy_buf[n_bytes++] = cur;
                cur = 0; bit_pos = 0;
                if (n_bytes >= sizeof(entropy_buf)) break;
            }
        }
    }
    if (bit_pos > 0 && n_bytes < sizeof(entropy_buf))
        entropy_buf[n_bytes++] = cur;

    SHA256(entropy_buf, n_bytes, rng_pool);
    rng_pool_used = 0;
    memcpy(&lfsr_state, rng_pool + 28, 4);
    if (lfsr_state == 0) lfsr_state = 0xACE1u;
}

static void RNG_GetBytes(uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
    {
        if (rng_pool_used < sizeof(rng_pool))
            buf[i] = rng_pool[rng_pool_used++];
        else {
            if ((i & 3u) == 0) LFSR_Next();
            buf[i] = (uint8_t)(lfsr_state >> ((i & 3u) * 8));
        }
    }
}

// SHA256
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g)   (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c)  (((a)&(b))^((a)&(c))^((b)&(c)))
#define SIG0(a)     (ROTR32(a,2)^ROTR32(a,13)^ROTR32(a,22))
#define SIG1(e)     (ROTR32(e,6)^ROTR32(e,11)^ROTR32(e,25))
#define sig0(x)     (ROTR32(x,7)^ROTR32(x,18)^((x)>>3))
#define sig1(x)     (ROTR32(x,17)^ROTR32(x,19)^((x)>>10))

static void SHA256_Transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[64], a,b,c,d,e,f,g,h,T1,T2;
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++)
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (int i = 0; i < 64; i++) {
        T1 = h + SIG1(e) + CH(e,f,g) + SHA256_K[i] + W[i];
        T2 = SIG0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void SHA256(const uint8_t *msg, uint32_t len, uint8_t digest[32])
{
    uint32_t state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    uint64_t bit_len = (uint64_t)len * 8;
    uint32_t pos = 0;
    while (len - pos >= 64) { SHA256_Transform(state, msg + pos); pos += 64; }
    uint32_t rem = len - pos;
    memcpy(block, msg + pos, rem);
    block[rem++] = 0x80;
    if (rem > 56) { memset(block + rem, 0, 64 - rem); SHA256_Transform(state, block); rem = 0; }
    memset(block + rem, 0, 56 - rem);
    for (int i = 7; i >= 0; i--) block[56 + (7 - i)] = (uint8_t)(bit_len >> (i * 8));
    SHA256_Transform(state, block);
    for (int i = 0; i < 8; i++) {
        digest[i*4+0] = (uint8_t)(state[i] >> 24); digest[i*4+1] = (uint8_t)(state[i] >> 16);
        digest[i*4+2] = (uint8_t)(state[i] >>  8); digest[i*4+3] = (uint8_t)(state[i]);
    }
}

// Hamming
static uint8_t Hamming_ComputeSyndrome(const uint8_t *data, uint32_t nbits)
{
    uint8_t syn = 0;
    for (uint32_t i = 0; i < nbits; i++)
        if ((data[i / 8] >> (i % 8)) & 1u)
            syn ^= (uint8_t)(i + 1);
    return syn;
}

static void Hamming_Correct(uint8_t *buf, uint8_t error_syndrome)
{
    if (error_syndrome == 0) return;

    uint32_t e = (uint32_t)error_syndrome - 1u;
    if (e < KEY_BITS)
        buf[e / 8] ^= (uint8_t)(1u << (e % 8));   // flip
}

// Phase 1: Generate
static void FuzzyExtractor_Generate(void)
{
    RNG_GetBytes(C, KEY_BITS / 8);

    Syn = Hamming_ComputeSyndrome(C, KEY_BITS);

    for (int i = 0; i < KEY_BITS / 8; i++)
        W[i] = Y[i] ^ C[i];

    SHA256(Y, KEY_BITS / 8, Key);
}

// Phase 2: Reproduce
static int FuzzyExtractor_Reproduce(const uint8_t *Y_prime,
                                    uint8_t *C_prime_out,
                                    uint8_t *C_out,
                                    uint8_t *Y_rec_out,
                                    uint8_t *Key_out)
{
    uint8_t C_prime[KEY_BITS / 8];
    for (int i = 0; i < KEY_BITS / 8; i++)
        C_prime[i] = Y_prime[i] ^ W[i];
    if (C_prime_out) memcpy(C_prime_out, C_prime, KEY_BITS / 8);

    uint8_t syn_prime    = Hamming_ComputeSyndrome(C_prime, KEY_BITS);
    uint8_t err_syndrome = syn_prime ^ Syn;
    if (err_syndrome > KEY_BITS) return -1;

    uint8_t C_corrected[KEY_BITS / 8];
    memcpy(C_corrected, C_prime, KEY_BITS / 8);
    Hamming_Correct(C_corrected, err_syndrome);
    if (C_out) memcpy(C_out, C_corrected, KEY_BITS / 8);

    uint8_t Y_rec[KEY_BITS / 8];
    for (int i = 0; i < KEY_BITS / 8; i++)
        Y_rec[i] = C_corrected[i] ^ W[i];
    if (Y_rec_out) memcpy(Y_rec_out, Y_rec, KEY_BITS / 8);

    if (Key_out) SHA256(Y_rec, KEY_BITS / 8, Key_out);

    return (err_syndrome != 0) ? 1 : 0;
}

int main(void)
{
    PUF_CaptureRaw();
    PUF_ComputeWeights();
    PUF_SelectMask();
    PUF_ApplyMask();
    RNG_Init();
    FuzzyExtractor_Generate();

    HAL_Init();
    SystemClock_Config();
    MX_GTZC_S_Init();
    MX_GPIO_Init();
    MX_USART1_UART_Init();
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("\r\n================================================\r\n");
    printf("          SRAM PUF + Fuzzy Extractor\r\n");
    printf("================================================\r\n");

    printf("\r\n[GENERATE]\r\n");
    PrintHex("PUF RESPONSE Y    (128-bit, sau bit selection)", Y,   KEY_BITS / 8);
    PrintHex("CODEWORD C        (128-bit, ngẫu nhiên)",       C,   KEY_BITS / 8);
    printf("\r\n=== HELPER DATA SYNDROME (Syn = syndrome(C)) ===\r\n");
    printf("Syn = 0x%02X\r\n", Syn);
    PrintHex("HELPER DATA W     (W = Y XOR C)",               W,   KEY_BITS / 8);
    PrintHex("KEY               (SHA-256(C))",                Key, 32);

    // Reproduce
    printf("\r\n================================================\r\n");
    printf("[REPRODUCE]\r\n");
    printf("================================================\r\n");

    uint8_t Y_prime[KEY_BITS / 8];
    memcpy(Y_prime, Y, KEY_BITS / 8);

    uint8_t C_prime_buf[KEY_BITS / 8];
    uint8_t C_buf      [KEY_BITS / 8];
    uint8_t Y_rec_buf  [KEY_BITS / 8];
    uint8_t Key_reproduced[32];

    PrintHex("Y'", Y_prime, KEY_BITS / 8);

    int result = FuzzyExtractor_Reproduce(Y_prime,
                                          C_prime_buf,
                                          C_buf,
                                          Y_rec_buf,
                                          Key_reproduced);

    if (result < 0) {
        printf("\r\n[FAIL] Reproduce that bai: >= 2 bit loi!\r\n");
    } else {
        printf("\r\nSo bit da sua: %d\r\n", result);

        PrintHex("C' = Y' XOR W        (sau XOR thu nhat)",     C_prime_buf, KEY_BITS / 8);
        PrintHex("C  = Hamming(C')     (sau Hamming correction)", C_buf,       KEY_BITS / 8);
        PrintHex("Y  = C XOR W         (sau XOR thu hai)",        Y_rec_buf,   KEY_BITS / 8);
        PrintHex("KEY = SHA-256(Y)     (256-bit key tai tao)",    Key_reproduced, 32);

        if (memcmp(Y, Y_rec_buf, KEY_BITS / 8) == 0)
            printf("\r\n[OK] Y phuc hoi KHOP voi Y goc!\r\n");
        else
            printf("\r\n[WARN] Y phuc hoi KHONG KHOP Y goc.\r\n");

        if (memcmp(Key, Key_reproduced, 32) == 0)
            printf("\r\n[OK] Key reproduced KHOP voi Key goc!\r\n");
        else
            printf("\r\n[FAIL] Key reproduced KHONG KHOP!\r\n");
    }

    HAL_Delay(100);
    NonSecure_Init();
    while (1) {}
}

static void NonSecure_Init(void)
{
    funcptr_NS NonSecure_ResetHandler;
    SCB_NS->VTOR = VTOR_TABLE_NS_START_ADDR;
    __TZ_set_MSP_NS((*(uint32_t *)VTOR_TABLE_NS_START_ADDR));
    NonSecure_ResetHandler = (funcptr_NS)(*((uint32_t *)(VTOR_TABLE_NS_START_ADDR + 4U)));
    NonSecure_ResetHandler();
}

void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE3);
    while (!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {}
    RCC_OscInitStruct.OscillatorType      = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState            = RCC_HSI_ON;
    RCC_OscInitStruct.HSIDiv              = RCC_HSI_DIV2;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState        = RCC_PLL_NONE;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) Error_Handler();
    RCC_ClkInitStruct.ClockType      = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                                     | RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2
                                     | RCC_CLOCKTYPE_PCLK3;
    RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_HSI;
    RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB3CLKDivider = RCC_HCLK_DIV1;
    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK) Error_Handler();
    __HAL_FLASH_SET_PROGRAM_DELAY(FLASH_PROGRAMMING_DELAY_0);
}

static void MX_GTZC_S_Init(void)
{
    MPCBB_ConfigTypeDef MPCBB_Area_Desc = {0};
    if (HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_USART1,
            GTZC_TZSC_PERIPH_SEC | GTZC_TZSC_PERIPH_NPRIV) != HAL_OK) Error_Handler();
    MPCBB_Area_Desc.SecureRWIllegalMode = GTZC_MPCBB_SRWILADIS_ENABLE;
    MPCBB_Area_Desc.InvertSecureState   = GTZC_MPCBB_INVSECSTATE_NOT_INVERTED;
    for (int i = 0; i < 20; i++) {
        MPCBB_Area_Desc.AttributeConfig.MPCBB_SecConfig_array[i]  = 0x00000000;
        MPCBB_Area_Desc.AttributeConfig.MPCBB_PrivConfig_array[i] = 0xFFFFFFFF;
    }
    MPCBB_Area_Desc.AttributeConfig.MPCBB_LockConfig_array[0] = 0x00000000;
    if (HAL_GTZC_MPCBB_ConfigMem(SRAM3_BASE, &MPCBB_Area_Desc) != HAL_OK) Error_Handler();
}

static void MX_USART1_UART_Init(void)
{
    huart1.Instance            = USART1;
    huart1.Init.BaudRate       = 115200;
    huart1.Init.WordLength     = UART_WORDLENGTH_8B;
    huart1.Init.StopBits       = UART_STOPBITS_1;
    huart1.Init.Parity         = UART_PARITY_NONE;
    huart1.Init.Mode           = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl      = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling   = UART_OVERSAMPLING_16;
    huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
    huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
    huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
    if (HAL_UART_Init(&huart1) != HAL_OK) Error_Handler();
    if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK) Error_Handler();
    if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK) Error_Handler();
    if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK) Error_Handler();
}

static void MX_GPIO_Init(void) { __HAL_RCC_GPIOB_CLK_ENABLE(); }

void Error_Handler(void) { __disable_irq(); while (1) {} }

#ifdef USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line) { (void)file; (void)line; }
#endif
