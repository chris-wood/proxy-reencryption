#include <iostream>
#include <openssl/bn.h>

using namespace std;

int main()
{
	cout << "Hello" << endl;

	BIGNUM num;
	int success = BN_generate_prime_ex(&num, 3072, 1, NULL, NULL, NULL);
	cout << success << endl;
	cout << num << endl;

	return 0;
}