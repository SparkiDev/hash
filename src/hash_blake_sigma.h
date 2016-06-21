/*
 * Copyright (c) 2016 Sean Parkinson (sparkinson@iprimus.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


/* This code is based on:
 *   RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication Code
 *              (MAC)
 */

#define SIGMA_0_0	0
#define SIGMA_1_0	1
#define SIGMA_2_0	2
#define SIGMA_3_0	3
#define SIGMA_4_0	4
#define SIGMA_5_0	5
#define SIGMA_6_0	6
#define SIGMA_7_0	7
#define SIGMA_8_0	8
#define SIGMA_9_0	9
#define SIGMA_10_0	10
#define SIGMA_11_0	11
#define SIGMA_12_0	12
#define SIGMA_13_0	13
#define SIGMA_14_0	14
#define SIGMA_15_0	15
#define SIGMA_0_1	14
#define SIGMA_1_1	10
#define SIGMA_2_1	4
#define SIGMA_3_1	8
#define SIGMA_4_1	9
#define SIGMA_5_1	15
#define SIGMA_6_1	13
#define SIGMA_7_1	6
#define SIGMA_8_1	1
#define SIGMA_9_1	12
#define SIGMA_10_1	0
#define SIGMA_11_1	2
#define SIGMA_12_1	11
#define SIGMA_13_1	7
#define SIGMA_14_1	5
#define SIGMA_15_1	3
#define SIGMA_0_2	11
#define SIGMA_1_2	8
#define SIGMA_2_2	12
#define SIGMA_3_2	0
#define SIGMA_4_2	5
#define SIGMA_5_2	2
#define SIGMA_6_2	15
#define SIGMA_7_2	13
#define SIGMA_8_2	10
#define SIGMA_9_2	14
#define SIGMA_10_2	3
#define SIGMA_11_2	6
#define SIGMA_12_2	7
#define SIGMA_13_2	1
#define SIGMA_14_2	9
#define SIGMA_15_2	4
#define SIGMA_0_3	7
#define SIGMA_1_3	9
#define SIGMA_2_3	3
#define SIGMA_3_3	1
#define SIGMA_4_3	13
#define SIGMA_5_3	12
#define SIGMA_6_3	11
#define SIGMA_7_3	14
#define SIGMA_8_3	2
#define SIGMA_9_3	6
#define SIGMA_10_3	5
#define SIGMA_11_3	10
#define SIGMA_12_3	4
#define SIGMA_13_3	0
#define SIGMA_14_3	15
#define SIGMA_15_3	8
#define SIGMA_0_4	9
#define SIGMA_1_4	0
#define SIGMA_2_4	5
#define SIGMA_3_4	7
#define SIGMA_4_4	2
#define SIGMA_5_4	4
#define SIGMA_6_4	10
#define SIGMA_7_4	15
#define SIGMA_8_4	14
#define SIGMA_9_4	1
#define SIGMA_10_4	11
#define SIGMA_11_4	12
#define SIGMA_12_4	6
#define SIGMA_13_4	8
#define SIGMA_14_4	3
#define SIGMA_15_4	13
#define SIGMA_0_5	2
#define SIGMA_1_5	12
#define SIGMA_2_5	6
#define SIGMA_3_5	10
#define SIGMA_4_5	0
#define SIGMA_5_5	11
#define SIGMA_6_5	8
#define SIGMA_7_5	3
#define SIGMA_8_5	4
#define SIGMA_9_5	13
#define SIGMA_10_5	7
#define SIGMA_11_5	5
#define SIGMA_12_5	15
#define SIGMA_13_5	14
#define SIGMA_14_5	1
#define SIGMA_15_5	9
#define SIGMA_0_6	12
#define SIGMA_1_6	5
#define SIGMA_2_6	1
#define SIGMA_3_6	15
#define SIGMA_4_6	14
#define SIGMA_5_6	13
#define SIGMA_6_6	4
#define SIGMA_7_6	10
#define SIGMA_8_6	0
#define SIGMA_9_6	7
#define SIGMA_10_6	6
#define SIGMA_11_6	3
#define SIGMA_12_6	9
#define SIGMA_13_6	2
#define SIGMA_14_6	8
#define SIGMA_15_6	11
#define SIGMA_0_7	13
#define SIGMA_1_7	11
#define SIGMA_2_7	7
#define SIGMA_3_7	14
#define SIGMA_4_7	12
#define SIGMA_5_7	1
#define SIGMA_6_7	3
#define SIGMA_7_7	9
#define SIGMA_8_7	5
#define SIGMA_9_7	0
#define SIGMA_10_7	15
#define SIGMA_11_7	4
#define SIGMA_12_7	8
#define SIGMA_13_7	6
#define SIGMA_14_7	2
#define SIGMA_15_7	10
#define SIGMA_0_8	6
#define SIGMA_1_8	15
#define SIGMA_2_8	14
#define SIGMA_3_8	9
#define SIGMA_4_8	11
#define SIGMA_5_8	3
#define SIGMA_6_8	0
#define SIGMA_7_8	8
#define SIGMA_8_8	12
#define SIGMA_9_8	2
#define SIGMA_10_8	13
#define SIGMA_11_8	7
#define SIGMA_12_8	1
#define SIGMA_13_8	4
#define SIGMA_14_8	10
#define SIGMA_15_8	5
#define SIGMA_0_9	10
#define SIGMA_1_9	2
#define SIGMA_2_9	8
#define SIGMA_3_9	4
#define SIGMA_4_9	7
#define SIGMA_5_9	6
#define SIGMA_6_9	1
#define SIGMA_7_9	5
#define SIGMA_8_9	15
#define SIGMA_9_9	11
#define SIGMA_10_9	9
#define SIGMA_11_9	14
#define SIGMA_12_9	3
#define SIGMA_13_9	12
#define SIGMA_14_9	13
#define SIGMA_15_9	0
#define SIGMA_0_10	0
#define SIGMA_1_10	1
#define SIGMA_2_10	2
#define SIGMA_3_10	3
#define SIGMA_4_10	4
#define SIGMA_5_10	5
#define SIGMA_6_10	6
#define SIGMA_7_10	7
#define SIGMA_8_10	8
#define SIGMA_9_10	9
#define SIGMA_10_10	10
#define SIGMA_11_10	11
#define SIGMA_12_10	12
#define SIGMA_13_10	13
#define SIGMA_14_10	14
#define SIGMA_15_10	15
#define SIGMA_0_11	14
#define SIGMA_1_11	10
#define SIGMA_2_11	4
#define SIGMA_3_11	8
#define SIGMA_4_11	9
#define SIGMA_5_11	15
#define SIGMA_6_11	13
#define SIGMA_7_11	6
#define SIGMA_8_11	1
#define SIGMA_9_11	12
#define SIGMA_10_11	0
#define SIGMA_11_11	2
#define SIGMA_12_11	11
#define SIGMA_13_11	7
#define SIGMA_14_11	5
#define SIGMA_15_11	3

/**
 * Perform one iteration of the mixing operations.
 *
 * @param [in] s  The state.
 * @param [in] d  The message data.
 * @param [in] i  The iteration number.
 */
#define MIX_G_I(s, d, i)					\
do								\
{								\
    MIX_G(s, 0, 4,  8, 12, d[SIGMA_0_##i ], d[SIGMA_1_##i ]);	\
    MIX_G(s, 1, 5,  9, 13, d[SIGMA_2_##i ], d[SIGMA_3_##i ]);	\
    MIX_G(s, 2, 6, 10, 14, d[SIGMA_4_##i ], d[SIGMA_5_##i ]);	\
    MIX_G(s, 3, 7, 11, 15, d[SIGMA_6_##i ], d[SIGMA_7_##i ]);	\
    MIX_G(s, 0, 5, 10, 15, d[SIGMA_8_##i ], d[SIGMA_9_##i ]);	\
    MIX_G(s, 1, 6, 11, 12, d[SIGMA_10_##i], d[SIGMA_11_##i]);	\
    MIX_G(s, 2, 7,  8, 13, d[SIGMA_12_##i], d[SIGMA_13_##i]);	\
    MIX_G(s, 3, 4,  9, 14, d[SIGMA_14_##i], d[SIGMA_15_##i]);	\
}								\
while (0)

