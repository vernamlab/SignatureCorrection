#~/bin/bash
# $ time sudo sh rowhammer.sh
clear
clear
rm -f test_dilithium2
cd .. ; make test/test_dilithium2; cd test

rm -f pre.txt
rm -f online.txt
rm -f unmapped.txt
touch unmapped.txt
rm -f faulty_signatures.txt

# Infinite while loop
while :
do
	echo 1 | sudo tee /proc/sys/vm/compact_memory
	sudo date >> pre.txt
	sudo date >> online.txt
	sudo ./test_dilithium2
done
