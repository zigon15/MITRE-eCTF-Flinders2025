/**
 * @file "crypto_test.h"
 * @author Simon Rosenzweig
 * @brief Test functions for crypto implementation
 * @date 2025
 *
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef CRYPTO_TEST_H
#define CRYPTO_TEST_H

//---------- Public Function Prototypes ----------//

/** @brief Tests AES ECB implementation
 *
 * @return 0 if all test pass, 1 if any test fails
 */
int crypto_test_AES_ECB(void);

/** @brief Tests AES CTR implementation
 *
 * @return 0 if all test pass, 1 if any test fails
 */
int crypto_test_AES_CTR(void);

/** @brief Tests CMAC implementation
 *
 * @return 0 if all test pass, 1 if any test fails
 */
int crypto_test_CMAC(void);


#endif

