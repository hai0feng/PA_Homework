#include "encryption.hpp"
#include "alu.hpp"
#include "matrix.hpp"
#include <iostream>
#include <sys/time.h>


int ShiftDotProduct(int* inputs, int * We,const int cols){
	int result=0;
	for(int i=0; i<cols; i++){
		if(We[i]<0){
			for( int j=0; j<-We[i]; j++){
				inputs[i]=inputs[i]>>1;
			}
		}
		else if(We[i]>0){
			for( int j=0; j<We[i]; j++){
				inputs[i]=inputs[i]<<1;
			}} 
		result=result+inputs[i];
	}
	return result;
}


//Plaintext Max operations and verification
int max(int A, int B){
	if(A>B) return A;
	else return B;
}

// elementary full comparator gate that is used to compare the i-th bit:
//   input: ai and bi the i-th bit of a and b
//          lsb_carry: the result of the comparison on the lowest bits
//   algo: if (a==b) return lsb_carry else return b 
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

// this function compares two multibit words, and puts the max in result
void maximum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i=0; i<nb_bits-1; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
   //we need to handel the comparison between positive number and negative number
    LweSample* msb_nota = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* msb_notb = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* msb_nota_and_b = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* msb_notb_and_a = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* msb_notb_and_a_or_msb_notb_and_a = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* not_tmps = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    bootsNOT(msb_nota, &a[nb_bits-1], bk);
    bootsNOT(msb_notb, &b[nb_bits-1], bk);
    bootsAND(msb_nota_and_b, msb_nota, &b[nb_bits-1], bk);
    bootsAND(msb_notb_and_a, msb_notb, &a[nb_bits-1], bk);
    bootsOR(msb_notb_and_a_or_msb_notb_and_a, msb_notb_and_a, msb_nota_and_b, bk);
    bootsNOT(not_tmps, &tmps[0], bk);
    bootsMUX(&tmps[0], msb_notb_and_a_or_msb_notb_and_a, not_tmps, &tmps[0], bk);
    //tmps[0] is the result of the comparaison: 0 if a is larger, 1 if b is larger
    //select the max and copy it to the result
    for (int i=0; i<nb_bits; i++) {
        bootsMUX(&result[i], &tmps[0], &a[i], &b[i], bk);
    }
    delete_gate_bootstrapping_ciphertext_array(2, tmps);    
}

void ReLU(LweSample* result, const LweSample* a,const int bits,const TFheGateBootstrappingCloudKeySet* ck){
	LweSample* b=new_gate_bootstrapping_ciphertext_array(bits, ck->params);
	zero(b, ck, bits);
	maximum(result, a, b, bits, ck);
}


int verify(int A, int B){
    if (A==B){printf("Verify Sucess!");}
    else{printf("There is difference between plaintext result and decrypted result!");}
}

int main(){
    const double clocks2seconds = 1. / CLOCKS_PER_SEC;
	// setup parameters
	typedef int8_t num_type ;
	size_t bits = 8;
	const int minimum_lambda = 80;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
	const TFheGateBootstrappingSecretKeySet* sk = new_random_gate_bootstrapping_secret_keyset(params);
	const TFheGateBootstrappingCloudKeySet* ck = &sk->cloud;
	
    printf("Multiple \n");
    int input_size=8;
    int *A = new int[input_size];
	int *B = new int[input_size];
    printf("A=[");
	for(int i=0; i< input_size; i++){
		A[i]=i;
        printf(" %d", A[i]);
	}
        
    printf("]\nB=[");
	for(int i=0; i< input_size; i++){
		B[i]=i;
	    printf(" %d", B[i]);
	}
	printf("]\n");
        

	LweSample **Enc_A=new LweSample*[input_size];
	LweSample **Enc_B=new LweSample*[input_size];
	LweSample **Enc_result = new LweSample*[input_size];
	for(int i1 = 0; i1 < input_size; i1++) {
		Enc_A[i1] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
		Enc_B[i1] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);	
		Enc_result[i1] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
	}

	for(num_type i=0; i<input_size;i++){
		encrypt<num_type>(Enc_A[i], i, sk);
		encrypt<num_type>(Enc_B[i], i, sk);
	}

    elem_mult(Enc_result, Enc_A, Enc_B, input_size, ck, bits);
	int tempt;
    for(int i=0; i<input_size; i++){
    tempt = decrypt<num_type>(Enc_result[i], sk);
        printf("Decrypted Result:%d\n",tempt);
    }

    return 0;    
}
