Hash Algorithms
===============

Open Source Hash Algorithms Implementation

Written by Sean Parkinson (sparkinson@iprimus.com.au)

For information on copyright see: COPYRIGHT.md

Contents of Repository
----------------------

This code implements a number of hash algorithms including:
 - SHA-224, SHA-256, SHA-384, SHA-512
 - SHA-512_224 SHA-512_256
 - SHA3-224, SHA3-256, SHA3-384, SHA3-512
 - BLAKE2b-224, BLAKE2b-256, BLAKE2b-384, BLAKE2b-512
 - BLAKE2s-224, BLAKE2s-256

There is a common API with which to chose and use a hash algorithm.

The code is fast C.
The library can be compiled to use OpenSSL for SHA-2 algorithms.

Building
--------

make

Testing
-------

Run all tests: hash_test

Run tests on internal implementation: hash_test -int

Run all algorithms and calculate speed: hash_test -speed

Performance
-----------

Examples of hash_test output on a 3.4 GHz Intel Ivy Bridge CPU:

```
./hash_test -speed

Cycles/sec: 3400273394
SHA-1 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 2650252 0.413      530 6415610   33.14 102596614  102.597
    64: 3516311 1.020      986 3448553   15.41 220606625  220.607
   256: 1457468 1.003     2339 1453729    9.14 372106742  372.107
  1024:  434262 0.992     7765  437897    7.58 448394186  448.394
  8192:   57872 1.000    58757   57870    7.17 474064571  474.065
 16384:   29086 0.997   116508   29184    7.11 478163850  478.164
SHA-224 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 3320579 1.002     1025 3317339   64.10  53045332   53.045
    64: 1806734 1.034     1946 1747314   30.41 111796735  111.797
   256:  715395 0.991     4708  722233   18.39 184870629  184.871
  1024:  221227 1.025    15753  215849   15.38 221028468  221.028
  8192:   29433 1.004   116011   29309   14.16 240106150  240.106
 16384:   14770 1.002   230683   14740   14.08 241499974  241.500
SHA-256 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 3304444 1.007     1036 3282117   64.75  52513105   52.513
    64: 1738381 1.007     1969 1726903   30.77 110499355  110.499
   256:  716601 1.002     4753  715395   18.57 183129807  183.130
  1024:  214650 0.990    15686  216771   15.32 221966915  221.967
  8192:   29150 0.998   116446   29200   14.21 239207899  239.208
 16384:   14640 0.997   231611   14680   14.14 240532563  240.533
SHA-384 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 2260820 1.006     1512 2248858   94.56  35958439   35.958
    64: 2262324 1.007     1513 2247371   23.64 143828648  143.829
   256:  830347 1.003     4105  828324   16.04 212023832  212.024
  1024:  286870 1.013    12010  283120   11.73 289891589  289.892
  8192:   35238 0.878    84753   40119   10.35 328658112  328.658
 16384:   20254 1.005   168804   20143   10.30 330026562  330.027
SHA-512 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 2346634 1.013     1467 2317841   91.70  37081656   37.082
    64: 2328954 1.010     1474 2306834   23.04 147591151  147.591
   256:  842903 1.001     4037  842277   15.77 215597231  215.597
  1024:  288868 1.003    11806  288012   11.53 294923966  294.924
  8192:   34961 0.881    85636   39706   10.45 325270274  325.270
 16384:   20166 1.007   169844   20019   10.37 328007171  328.007
SHA-512_224 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 2406421 1.003     1416 2401323   88.53  38406700   38.407
    64: 2386156 1.003     1429 2379477   22.33 152243289  152.243
   256:  856707 1.005     3990  852198   15.59 218155387  218.155
  1024:  289138 1.001    11768  288942   11.49 295863868  295.864
  8192:   34649 0.862    84619   40183   10.33 329181332  329.181
 16384:   20281 1.000   167590   20289   10.23 332417003  332.417
SHA-512_256 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 2381143 1.002     1430 2377813   89.41  38031637   38.032
    64: 2374492 1.018     1458 2332149   22.78 149253701  149.254
   256:  835242 0.994     4046  840403   15.81 215106477  215.106
  1024:  288893 1.004    11818  287719   11.54 294606291  294.606
  8192:   38805 0.968    84845   40076   10.36 328303940  328.304
 16384:   20153 0.995   167910   20250   10.25 331784145  331.784
SHA-3_224 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 1800038 1.002     1892 1797184  118.31  28740137   28.740
    64: 1770053 1.001     1922 1769132   30.04 113182108  113.182
   256:  982737 0.989     3421  993941   13.37 254401145  254.401
  1024:  273333 1.003    12475  272567   12.18 279091674  279.092
  8192:   33404 0.848    86308   39396   10.54 322738923  322.739
 16384:   19735 1.000   172236   19741   10.51 323451098  323.451
SHA-3_256 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 1830071 1.002     1862 1826140  116.39  29214668   29.215
    64: 1790559 0.998     1894 1795286   29.60 114858463  114.858
   256:  978777 1.002     3480  977090   13.60 250099478  250.099
  1024:  273070 1.003    12487  272305   12.20 278822990  278.823
  8192:   36056 0.979    92320   36831   11.27 301720079  301.720
 16384:   18289 0.983   182728   18608   11.15 304879578  304.880
SHA-3_384 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 1949698 1.001     1745 1948580  109.11  31163419   31.163
    64: 1887991 1.000     1800 1889040   28.14 120846932  120.847
   256:  732501 1.002     4649  731398   18.16 187230029  187.230
  1024:  231720 1.002    14700  231311   14.36 236855762  236.856
  8192:   29931 0.997   113244   30026   13.82 245972058  245.972
 16384:   15040 1.000   226131   15036   13.80 246361170  246.361
SHA-3_512 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 2008430 0.959     1624 2093764  101.52  33492473   33.492
    64: 2074602 1.002     1642 2070812   25.66 132528272  132.528
   256:  578474 0.996     5855  580746   22.87 148654254  148.654
  1024:  159907 1.002    21312  159547   20.81 163376271  163.376
  8192:   21237 1.007   161252   21086   19.68 172741515  172.742
 16384:   10629 1.000   320015   10625   19.53 174085811  174.086
BLAKE2b_512 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 5574218 0.999      609 5583371   38.09  89278118   89.278
    64: 5629591 1.006      607 5601768    9.49 358113361  358.113
   256: 2928745 1.001     1162 2926224    4.54 748727974  748.728
  1024:  756793 1.001     4498  755952    4.39 773927296  773.927
  8192:   89115 0.934    35624   95448    4.35 781911433  781.911
 16384:   47804 1.000    71159   47784    4.34 782891168  782.891
BLAKE2s_256 C
    Op      ops  secs     c/op   ops/s     c/B       B/s     mB/s
    16: 6759986 1.000      502 6773452   31.43 108174735  108.175
    64: 6855389 1.002      497 6841596    7.77 437699840  437.700
   256: 1753622 0.975     1891 1798135    7.39 460304168  460.304
  1024:  458010 1.001     7434  457394    7.26 468357223  468.357
  8192:   57482 1.001    59183   57453    7.22 470651688  470.652
 16384:   28771 1.000   118232   28759    7.22 471192124  471.192
```

