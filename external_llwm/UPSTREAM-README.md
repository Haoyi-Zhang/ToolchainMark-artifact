# MA David

## Register Expansion
The first Watermark (Register Expansion Watermark) works by expanding suitable 4-byte integer variables to 8-byte variables. The additional 4-bytes can be used to store the watermark. We compute the watermark with already present computations (where a watermark present in one of the operands can be inherited) or by introduction additional instructions that modifying the upper bytes, s.t. the watermark is dependent on the parameters of the functions it is inserted in. The correct secret input in the parameters will then yield the correct watermark in the upper bits.


## SemaCall
The SemaCall Watermark, formally known as the Patching-LibC-Watermark is the second one.
Calls to selected functions from libc are adjusted with custom implementations that include the watermark dynamically from datetime, user-input or whatever dynamic information source is available for that function. 
From the data first a hash value is generated that is checked for a custom watermark key. If the key is provided,
the hash should match and the additional code should calculate the watermark value from the key and print it.
Currently supported functions: atoi, atol, strtol, fgets, gets, getline, time

## Sidedata
Stack allocated arrays are assumed to hold the key. They are duplicated and the key to value transformation
done with polynom generation. Again an easter block is generated and triggered, if the key is present.
It then prints the generated watermark value on standrd out.

## Structure & Building

- `thesis/` latex source code and pdf of the master thesis
- `paper/` latex source code and pdf of the paper 
- `presentation/` latex source code and pdf of the presentation of the thesis
- `src/llvm-middleend-watermark` source code of watermark generators and helper scripts

The Register Expansion Watermark, SemaCall Watermark and sidedata watermark work in the middleend of LLVM, by being compiled 
within LLVM and then dynamically loaded as a plugin (the library is created in `src/llvm-middleend-watermark/build/lib/<watermark>.so` 
(something else if you don't work in linux). It also is patched into the built optimization programs of llvm i.e. 
`bin/opt`, but as a plugin it can be loaded by an already installed version of `opt` 
(don't use the patched `opt` to load the watermark, since that redefines the command line arguments and leads to errors).
An patched version of clang can be built as well.

Therefore it is necessary to clone llvm, insert our watermark and compile it. The cloning and correct insertion of 
the necessary files can be done with a simple shell script `src/llvm-middleend-watermark/init_llvm.sh`, execute it
inside of `src/llvm-middleend-watermark`, then you can build llvm with the watermark by running
```
cmake -S llvm -B build -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS=clang
cd build
make
```
If the polynomial message encoding or the character-wise-tailoring is to be used can be controlled by the `DONT_USE_POLYNOM` definitions in the corresponding LLVM passes.


## Usage
The patched version of `opt` can be used to include the watermark with:
```
opt -passes="default<$(OPTLEVEL)>,watermark_name"
```
(of course the corresponding watermark arguments have to be given additionally)

The shared libraries can be loaded in a standard version of `opt` with:
```
opt -load-pass-plugin watermark.so
```
and is then as capable as the patched version.

The corresponding arguments to activate the watermark and specify the watermarking message are:
- For Register Expansion: "-passes=register-expansion-watermark" (to add it to `opt`'s pipeline) 
                          "-watermark-val=\<integer\>" (for the value) 
                          "-watermark-key=\<integer\>" (for the key)
- For SemaCall: "-passes=semacall-watermark"
    * atoi: "-atoi-key=\<string with leading number\> -atoi-val=\<string\>"
    * gets: "-gets-key=\<string\> -gets-val=\<string\>"
    * time: "-time-key=\<timestamp\> -time-val=\<string\>"
- For Sidedata: "-passes=sidedata-watermark", "-sidedata-key=\<string\> -sidedata-val=\<string\>"

If the watermark was included in a function it will be printed on stdout of `opt`.

## Testing
We compiled a list of c and c++ test cases to test the functionality of opt in the folder `src/llvm-test-suite` consisting of a
selection of the [llvm-test-suite](https://github.com/llvm/llvm-test-suite/) and [c-test-suite](https://github.com/c-testsuite/c-testsuite).
You can build it with `make` and run it with the given `test.py`. It supports several options, like only running the benchmarks,
see its help page (`python3 test.py -h`).
The statistics on the runtime of the benchmarks have been compiled by measuring the time it takes the script to finish `time python3 test.py -b`.
For more information see [src/llvm-test-suite/README.md](./src/llvm-test-suite/README.md)

## Experiments
Experiments like the polynom generator for function fitting and linear regression can be found in the experiments
folder.
