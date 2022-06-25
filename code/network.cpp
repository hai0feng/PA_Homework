#include "encryption.hpp"
#include "alu.hpp"
#include "matrix.hpp"
#include <iostream>
#include <sys/time.h>
#include <fstream>
#include <sstream>
#include "weight.hpp"
#include <omp.h>


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

void readImage(int image[10][784]) {
	ifstream file;
	file.open("./MNIST-test.txt", ios_base::in);

	if(!file.is_open()) {
		cout<<"Can not open file"<<endl;
	}

	string str;
	int index, value, label, size;
	char c;
	for(int i=0; i<10; i++) {
		getline(file,str);
		istringstream s(str);
		s >> label >> size;
		while(s >> index >> c >> value) {
			image[i][index] = value;
		}
	}
}

int main(){
	int image[10][784];
	readImage(image);
	//cout << image[0][202] << endl;

        const double clocks2seconds = 1. / CLOCKS_PER_SEC;
	// setup parameters
	typedef int8_t num_type ;
	size_t bits = 8;
	const int minimum_lambda = 80;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
	const TFheGateBootstrappingSecretKeySet* sk = new_random_gate_bootstrapping_secret_keyset(params);
	const TFheGateBootstrappingCloudKeySet* ck = &sk->cloud;
	clock_t bs_begin, bs_end;
	
	// initial
	int input_size = 1;
	/*LweSample ***Enc_image=new LweSample*[input_size][784];
	LweSample ***Enc_W1=new LweSample*[784][50];
	LweSample ***Enc_media1=new LweSample*[input_size][50];
	LweSample ***Enc_relu1=new LweSample*[input_size][50];
	LweSample ***Enc_W2=new LweSample*[50][10];
	LweSample ***Enc_media2=new LweSample*[input_size][10];
	LweSample ***Enc_result=new LweSample*[input_size][10];
	Enc_image=new LweSample*[input_size][784];
	Enc_W1=new LweSample*[784][50];
	Enc_media1=new LweSample*[input_size][50];
	Enc_relu1=new LweSample*[input_size][50];
	Enc_W2=new LweSample*[50][10];
	Enc_media2=new LweSample*[input_size][10];
	Enc_result=new LweSample*[input_size][10];
	*/
	LweSample **temp1 = new LweSample*[784];
	LweSample **temp2 = new LweSample*[50];
	LweSample *Enc_image[input_size][784];
	LweSample *Enc_W1[784][50];
	LweSample *Enc_media1[input_size][50];
	LweSample *Enc_relu1[input_size][50];
	LweSample *Enc_W2[50][10];
	LweSample *Enc_media2[input_size][10];
	LweSample *Enc_result[input_size][10];
	int result[input_size][10];
	
	for(int i=0; i<784; i++) {
		temp1[i] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
	}
	for(int i=0; i<50; i++) {
		temp2[i] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
	}
	for(int i1 = 0; i1 < input_size; i1++) {
		for(int i2=0; i2 < 784;i2++) {
			Enc_image[i1][i2] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
		}
	}
	for(int i1 = 0; i1 < 784; i1++) {
		for(int i2=0; i2 < 50;i2++) {
			Enc_W1[i1][i2] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
		}
	}
	for(int i1 = 0; i1 < input_size; i1++) {
		for(int i2=0; i2 < 50;i2++) {
			Enc_media1[i1][i2] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
			Enc_relu1[i1][i2] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
		}
	}
	for(int i1 = 0; i1 < 50; i1++) {
		for(int i2=0; i2 < 10;i2++) {
			Enc_W2[i1][i2] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
		}
	}
	for(int i1 = 0; i1 < input_size; i1++) {
		for(int i2=0; i2 < 10;i2++) {
			Enc_media2[i1][i2] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
			Enc_result[i1][i2] = new_gate_bootstrapping_ciphertext_array(bits, ck->params);
		}
	}
	
	//encrypt image and W1 W2
	bs_begin=clock();
	for(int i1=0; i1<input_size;i1++){
		for(int i2=0; i2<784; i2++){
			encrypt<num_type>(Enc_image[i1][i2], image[i1][i2], sk);
		}
	}
	bs_end=clock();
  	printf("encrypt time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);
	for(int i1=0; i1<784;i1++){
		for(int i2=0; i2<50; i2++){
			encrypt<num_type>(Enc_W1[i1][i2], W1[i1][i2], sk);
		}
	}
	for(int i1=0; i1<50;i1++){
		for(int i2=0; i2<10; i2++){
			encrypt<num_type>(Enc_W2[i1][i2], W2[i1][i2], sk);
		}
	}
	
	bs_begin = clock();
	for(int j=0; j<8; j++) {
		for(int k=0; k<784; k++){
			mult(temp1[k], Enc_image[0][k], Enc_W1[k][j], ck, bits);
		}
		seq_add(Enc_media1[0][j], temp1, 784, ck, bits);
	}
	bs_end = clock();
	printf("calculate1 time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin = clock();
	#pragma omp parallel for num_threads(4)
	for(int j=0; j<8; j++) {
		for(int k=0; k<784; k++){
			mult(temp1[k], Enc_image[0][k], Enc_W1[k][j], ck, bits);
		}
		seq_add(Enc_media1[0][j], temp1, 784, ck, bits);
	}
	bs_end = clock();
	printf("calculate2 time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin = clock();
	#pragma omp parallel for num_threads(8)
	for(int j=0; j<8; j++) {
		for(int k=0; k<784; k++){
			mult(temp1[k], Enc_image[0][k], Enc_W1[k][j], ck, bits);
		}
		seq_add(Enc_media1[0][j], temp1, 784, ck, bits);
	}
	bs_end = clock();
	printf("calculate3 time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin = clock();
	//mult(temp1[0], Enc_image[0][0], Enc_W1[0][0], ck, bits);
	//ReLU(temp1[0], temp1[0], bits, ck);
	//seq_add(Enc_media1[0][0], Enc_image[0], 784, ck, bits);
	//add(Enc_media1[0][0], Enc_media1[0][1], Enc_media1[0][1], ck, bits);
	/*for(int i=0; i<input_size; i++){
		for(int j=0; j<50; j++) {
			for(int k=0; k<784; k++){
				mult(temp1[k], Enc_image[i][k], Enc_W1[k][j], ck, bits);
			}
			seq_add(Enc_media1[i][j], temp1, 784, ck, bits);
			ReLU(Enc_result[i][j], Enc_media1[i][j], bits, ck);
		}
	}
	for(int i=0; i<input_size; i++){
		for(int j=0; j<10; j++) {
			for(int k=0; k<50; k++){
				mult(temp2[k], Enc_image[i][k], Enc_W1[k][j], ck, bits);
			}
			seq_add(Enc_result[i][j], temp2, 50, ck, bits);
		}
	}*/
	bs_end = clock();
	printf("calculate time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);

	/*bs_begin = clock();
	seq_add(Enc_media1[0][0], Enc_image[0], 784, ck, bits);
	bs_end = clock();
	printf("seq_add time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin = clock();
	reduce_add(Enc_media1[0][0], Enc_image[0], 784, ck, bits);
	bs_end = clock();
	printf("reduce_add time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin = clock();
	reduce_add_4(Enc_media1[0][0], Enc_image[0], 784, ck, bits);
	bs_end = clock();
	printf("reduce_add_4 time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);

	bs_begin = clock();
	reduce_add_8(Enc_media1[0][0], Enc_image[0], 784, ck, bits);
	bs_end = clock();
	printf("reduce_add_8 time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);*/

	bs_begin = clock();
	for(int i=0; i<input_size; i++){
		for(int j=0; j<input_size; j++){
			result[i][j] = decrypt<num_type>(Enc_result[i][j], sk);
		}
	}
	bs_end = clock();
	printf("decrypt time:%f s\n",(bs_end-bs_begin)*clocks2seconds/2);

	return 0;
}
