# Signature Correction Attack on Dilithium Signature Scheme
https://arxiv.org/abs/2203.00637
```
@article{islam2022signature,
  title={Signature Correction Attack on Dilithium Signature Scheme},
  author={Islam, Saad and Mus, Koksal and Singh, Richa and Schaumont, Patrick and Sunar, Berk},
  journal={arXiv preprint arXiv:2203.00637},
  year={2022}
}
```

## PREREQUISITES:

As we are targeting the AVX2 implementation, the processor must be atleast Haswell or above for AVX2 support.
We are using the round 3 submission package of dilithium from NIST's website, please make sure it compiles and runs without any errors from the following page:

https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions

We have added our SIGNATURE CORRECTION ATTACK code at the bottom of sign.c and calling it from test_dilithium.c

## INPUT FILES NEEDED:
Our signature correction attack needs the following two input files:
-	Victim's public key "pk.txt".
-	Faulty signatures "faulty_signatures.txt".

We have provided both files from our experiments. Our "faulty_signatures.txt" contains 7085 faulty signatures which is explained in Rowhammer section. The fault mechanism that we have used is Rowhammer attack but our signature correction attack is generic and works for any fault mechanism if the single bit flips are induced in the secret key s1 before the signing step z = y + c.s1 is executed, faults must be injected in time domain before NTT(s1). If you do not have any fault setup, you can also induce artificial bit flips inside the code to reproduce the signature correction attack.

## STEPS TO RUN:
```
$ cd signature_correction_dilithium2_round3/
$ make test/test_dilithium2
$ cd test
$ ./test_dilithium2
```

## RESULTS:

This should write the recovered key bits in "recovered_bits.txt" having 5,359 entries (for our "faulty_signatures.txt") in the following format:

- Col 1 -> Polynomial number in s1				(0-L),	L = 3 for security level 2
- Col 2 -> Coefficient number of the polynomial	(0-N),	N = 256
- Col 3 -> Bit index of the coefficient			(0-32),	0 = LSB
- Col 4 -> Value of the recovered bit				(0, 1)

Finally the MATLAB script "recovered_bits.m" can be used to generate a figure showing the recovered bits similar to Figure 5 in the paper. It also prints the number of unique key bits recovered, which is 3,735 in our case. The script takes "recovered_bits.txt" as input which we have also provided in recovered_bits.zip for verification.





# ROWHAMMER

## PREREQUISITES:
The Rowhammer experiments requires a DDR3 DRAM which is vulnerable to Rowhammer attack and needs some parameter settings which may vary from machine to machine, details of which can be seen in the comments inside the code.

## STEPS TO RUN:
```
$ cd rowhammer_dilithium2_round3/test/
$ sudo ./rowhammer.sh
```

The "rowhammer.sh" script will compile the "test_dilithium.c" which contains the pre-processing part of Rowhammer attack. The code uses "SPOILER" to detect contiguous memory followed by row conflict code for bank co-location. Then it tries to map the secret key "T" in a loop until it maps to the desired vulnerable physical address found by the Rowhammer. Once it is successfully mapped, the "crypto_sign" function is called, defined in "sign.c". There we have our online phase of Rowhammer before the signing step z = y + c.s1. To avoid system crashes, memory constraints, disk errors and synchronization problems caused by the Rowhammer attack when run independently, we have combined the attacker and the victim code but Rowhammer parts are highlighted using the comments.

At this point, a faulty signature is generated and stored in "faulty_signatures.txt", if it successfully passes the rejection check.
The script keeps on writing the faulty signatures until the target starts mapping to the previously mapped physical addresses. At this stage, you can stop the code and use the "faulty_signatures.txt" as an input to the signature correction code along with the public key "pk.txt". The "pre.txt" and "online.txt" show the time in seconds it took for the pre-processing and online phase of the attack.