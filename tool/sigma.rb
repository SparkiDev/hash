# Copyright (c) 2016 Sean Parkinson
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

a =
[
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 ],
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ]
]

File.readlines(File.dirname(__FILE__)+'/../license/license.c').each { |l| puts l }
puts
puts <<EOF
/* This code is based on:
 *   RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication Code
 *              (MAC)
 */
EOF
puts
0.upto(a.length-1) do |i|
  0.upto(a[i].length-1) do |j|
    puts "#define SIGMA_#{j}_#{i}\t#{a[i][j]}"
  end
end
puts <<EOF

/**
 * Perform one iteration of the mixing operations.
 *
 * @param [in] s  The state.
 * @param [in] d  The message data.
 * @param [in] i  The iteration number.
 */
#define MIX_G_I(s, d, i)					\\
do								\\
{								\\
    MIX_G(s, 0, 4,  8, 12, d[SIGMA_0_##i ], d[SIGMA_1_##i ]);	\\
    MIX_G(s, 1, 5,  9, 13, d[SIGMA_2_##i ], d[SIGMA_3_##i ]);	\\
    MIX_G(s, 2, 6, 10, 14, d[SIGMA_4_##i ], d[SIGMA_5_##i ]);	\\
    MIX_G(s, 3, 7, 11, 15, d[SIGMA_6_##i ], d[SIGMA_7_##i ]);	\\
    MIX_G(s, 0, 5, 10, 15, d[SIGMA_8_##i ], d[SIGMA_9_##i ]);	\\
    MIX_G(s, 1, 6, 11, 12, d[SIGMA_10_##i], d[SIGMA_11_##i]);	\\
    MIX_G(s, 2, 7,  8, 13, d[SIGMA_12_##i], d[SIGMA_13_##i]);	\\
    MIX_G(s, 3, 4,  9, 14, d[SIGMA_14_##i], d[SIGMA_15_##i]);	\\
}								\\
while (0)

EOF

