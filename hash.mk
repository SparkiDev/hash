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


all: $(LIBNAME) hash_test

HASH_OBJ=hash.o hash_sha1.o hash_sha256.o hash_sha512.o hash_sha3.o \
         hash_sha3_block.o hash_blake2b.o hash_blake2s.o random.o

%.o: src/%.c src/*.h include/*.h
	$(CC) -c $(CFLAGS) -o $@ $<

src/hash_sha3_block.c: tool/sha3.rb
	ruby tool/sha3.rb >src/hash_sha3_block.c
hash_sha3_block.o: src/hash_sha3_block.c src/*.h include/*.h
	$(CC) -c $(CFLAGS) ${CFLAGS_NO_OPT} -o $@ $<

$(LIBNAME): $(HASH_OBJ)
	$(LINK) $(LIBNAME) $(HASH_OBJ)

hash_test.o: test/hash_test.c
	$(CC) -c $(CFLAGS) -Isrc -o $@ $<
hash_test: hash_test.o $(LIBNAME)
	$(CC) -o $@ $^ $(LIBS)

clean:
	rm -f *.o
	rm -f hash_test
	rm -f $(LIBNAME)

