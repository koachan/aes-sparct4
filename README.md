An ESTREAM-compatible AES-CTR wrapper for SPARC T4 AES instructions
---

### What is this?

This is an AES-CTR wrapper around SPARC T4 AES instructions
([Oracle SPARC Architecture 2011](https://www.oracle.com/technetwork/server-storage/sun-sparc-enterprise/documentation/140521-ua2011-d096-p-ext-2306580.pdf),
section 7.3-7.4).

The code is written to be compatible with the
[eSTREAM testing framework](https://www.ecrypt.eu.org/stream/perf/),
just drop it into the submissions directory and run the benchmarks to try it out.

Of course, the usual disclaimer applies: This is experimental and unaudited code,
use it at your own risk.

### How fast is it?

Below is the comparison between my implementation and the benchmark
implementation included in the testing framework:

| Implementation                                  | Long Stream | 40 bytes  | 576 bytes | 1500 bytes | Imix      | Agility   | Key setup     | IV setup     |
|-------------------------------------------------|-------------|-----------|-----------|------------|-----------|-----------|---------------|--------------|
| bernstein/big-1/1                               | 29.80 cpb   | 42.90 cpb | 30.22 cpb | 30.05 cpb  | 31.03 cpb | 34.52 cpb | 269.11 cycles | 76.86 cycles |
| aes-sparct4                                     |  4.09 cpb   |  8.84 cpb |  4.36 cpb |  4.23 cpb  |  4.62 cpb |  7.48 cpb | 159.40 cycles | 73.32 cycles |

All tests were done on a 2.85 GHz SPARC T4 running Gentoo Linux with
Clang 12.0.0 compiler.

### Things to do

- Optimize it more.
  - OpenSSL managed to run 128-bit AES-CTR at about 2.65 cpb using
    a custom assembly loop.
- Add 192 and 256 bit key variants.
