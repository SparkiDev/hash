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

CC=gcc
CFLAGS=-O3 -m64 -Wall -Werror -Wextra -Wpedantic -DCPU_X86_64 -DCC_GCC -Iinclude
#CFLAGS=-g -m64 -Wall -Werror -Wextra -Wpedantic -DCPU_X86_64 -DCC_GCC -Iinclude
CFLAGS_NO_OPT=-O1
LIBS=
#CFLAGS+=-DHASH_SHA3_SMALL
#CFLAGS+=-DOPT_HASH_RDRAND
#CFLAGS+=-DOPT_HASH_OPENSSL
#CFLAGS+=-DOPT_HASH_OPENSSL_RAND
#LIBS+=-lcrypto
LINK=ar r
LIBNAME=libhash.a

include hash.mk

