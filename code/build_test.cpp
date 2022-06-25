#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

int main() {
	int image[10][784];

	ifstream file;
	file.open("./MNIST-test.txt", ios_base::in);

	if(!file.is_open()) {
		cout<<"Can not open file"<<endl;
	}

	/*stringstream s;
	s<<file.rdbuf();
	string str = s.str();*/
	string str;
	int index, value, label, size;
	char c;
	for(int i=0; i<10; i++) {
		getline(file,str);
		istringstream s(str);
		s >> label >> size;
		//cout << i << endl;
		while(s >> index >> c >> value) {
			image[i][index] = value;
		}
	}
	//cout << image[0][202] << endl;
	//cout << str << endl;
	return 0;
}


