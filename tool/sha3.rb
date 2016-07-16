#!/usr/local/bin/ruby

class SHA3
    @@index = [  1,
                10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
                15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
    ]
    @@rotate = [  0,
                  1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
                 27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
    ]
    @@r = [
      0x0000000000000001, 0x0000000000008082,
      0x800000000000808a, 0x8000000080008000,
      0x000000000000808b, 0x0000000080000001,
      0x8000000080008081, 0x8000000000008009,
      0x000000000000008a, 0x0000000000000088,
      0x0000000080008009, 0x000000008000000a,
      0x000000008000808b, 0x800000000000008b,
      0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080,
      0x000000000000800a, 0x800000008000000a,
      0x8000000080008081, 0x8000000000008080,
      0x0000000080000001, 0x8000000080008008
    ]

    def initialize(by_spec)
      @by_spec = by_spec
      @a = []
      0.upto(24) { |i| @a[i] = i }
    end

    def swap_rotl_24()
      t1 = @a[@@index[0]]
      1.upto(24) do |i|
        t2 = @a[@@index[i]]
        @a[@@index[i]] = t1
        t1 = t2
      end
    end

    def col_mix()
      0.upto(4) do |x|
        puts "    b[#{x}] = s[#{@a[x+0]}] ^ s[#{@a[x+5]}] ^ s[#{@a[x+10]}] ^ s[#{@a[x+15]}] ^ s[#{@a[x+20]}];"
      end
      0.upto(4) do |x|
        puts "    t = b[#{(x+4)%5}] ^ ROTL64(b[#{(x+1)%5}], 1);"
        puts "    s[#{@a[x+0]}]^=t; s[#{@a[x+5]}]^=t; s[#{@a[x+10]}]^=t; s[#{@a[x+15]}]^=t; s[#{@a[x+20]}]^=t;"
      end
    end

    def row_mix()
      0.upto(4) do |y|
        0.upto(4) do |x|
          1.upto(24) do |j|
            if @@index[j] == y*5+x
              puts "    s[#{@a[y*5+x]}] = ROTL64(s[#{@a[y*5+x]}], #{@@rotate[j]});"
              break
            end
          end
          puts "    b[#{x}] = s[#{@a[y*5+x]}];"
        end
        if @by_spec
          0.upto(4) do |x|
            puts "    s[#{@a[y*5+x]}] = b[#{x}] ^ (~b[#{(x+1)%5}] & b[#{(x+2)%5}]);"
          end
        else
          puts <<EOF
    {
        uint64_t t12, t34;

        t12 = (b[1] ^ b[2]); t34 = (b[3] ^ b[4]);
        s[#{@a[y*5+0]}] = b[0] ^ (b[2] &  t12);
        s[#{@a[y*5+1]}] =  t12 ^ (b[2] | b[3]);
        s[#{@a[y*5+2]}] = b[2] ^ (b[4] &  t34);
        s[#{@a[y*5+3]}] =  t34 ^ (b[4] | b[0]);
        s[#{@a[y*5+4]}] = b[4] ^ (b[1] & (b[0] ^ b[1]));
    }
EOF
        end
      end
    end

    def block()
      File.readlines(File.dirname(__FILE__)+'/../license/license.c').each { |l| puts l }
      puts <<EOF
#include <stdint.h>

#ifndef HASH_SHA3_SMALL
/**
 * Rotate a 64-bit value left.
 *
 * @param [in] a  The number to rotate left.
 * @param [in] r  The number od bits to rotate left.
 * @return  The rotated number.
 */
#define ROTL64(a, n)    (((a)<<(n))|((a)>>(64-(n))))

/**
 * The block operation performed on the state.
 *
 * @param [in] s  The state.
 */
void hash_keccak_block(uint64_t *s)
{
    uint64_t b[5], t;

EOF
      0.upto(23) do |i|
        col_mix()
        swap_rotl_24()
        row_mix()
        puts "    s[#{@a[0]}] ^= 0x#{@@r[i].to_s(16)}UL;"
      end
      puts "}"
      puts "#endif /* HASH_SHA3_SMALL */"
      puts
    end
end

sha3 = SHA3.new(false)
sha3.block

