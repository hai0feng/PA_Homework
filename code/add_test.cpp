#include "encryption.hpp"
#include "alu.hpp"
#include "matrix.hpp"
#include <iostream>
#include <sys/time.h>

int main(){
    const double clocks2seconds = 1. / CLOCKS_PER_SEC;
	// setup parameters
	typedef int8_t num_type ;
	size_t bits = 8;
	const int minimum_lambda = 80;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
	const TFheGateBootstrappingSecretKeySet* sk = new_random_gate_bootstrapping_secret_keyset(params);
	const TFheGateBootstrappingCloudKeySet* ck = &sk->cloud;
	
	printf("Add \n");    
	int8_t A = 23;    
	int8_t B = 65;
	printf("%d + %d: \n", A, B);
	//printf("%ld + %ld: \n", A, B);

	LweSample *Enc_A=new_gate_bootstrapping_ciphertext_array(bits, ck->params);
	LweSample *Enc_B=new_gate_bootstrapping_ciphertext_array(bits, ck->params);
	LweSample *Enc_result1 = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
	LweSample *Enc_result2 = new_gate_bootstrapping_ciphertext_array(bits, ck->params);

	encrypt<num_type>(Enc_A, A, sk);
	encrypt<num_type>(Enc_B, B, sk);

	clock_t bs_begin, bs_end;

	bs_begin=clock();
	full_adder(Enc_result1, Enc_A, Enc_B, bits, sk);
	bs_end=clock();
  	printf("full_adder time:%f\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin=clock();
	add(Enc_result2, Enc_A, Enc_B, ck, bits);
	bs_end=clock();
  	printf("add time:%f\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin=clock();
	p_add(Enc_result2, Enc_A, Enc_B, ck, bits);
	bs_end=clock();
  	printf("p_add time:%f\n",(bs_end-bs_begin)*clocks2seconds/2);

	//bs_begin=clock();
	//stone_add(Enc_result2, Enc_A, Enc_B, sk, ck, bits);
	//bs_end=clock();
  	//printf("stone_add time:%f\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin=clock();
	Kogge_add(Enc_result2, Enc_A, Enc_B, sk, ck, bits);
	bs_end=clock();
  	printf("Kogge_add time:%f\n",(bs_end-bs_begin)*clocks2seconds/2);

	int tempt;
        tempt = decrypt<num_type>(Enc_result1, sk);
        printf("Decrypted Result(full adder):%d\n",tempt);

	tempt = decrypt<num_type>(Enc_result2, sk);
        printf("Decrypted Result(add):%d\n",tempt);

    	return 0;    
}
