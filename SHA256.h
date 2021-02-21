
#ifndef SHA256_H
#define SHA256_H

#include <cstdint>
#include <cstring>
#include <array>

using namespace std;

class SHA256
{
private:
	uint64_t data_size;
	uint32_t chunk;
	uint32_t data_count[8];
	uint8_t chunk_count[64];

public:
	SHA256()
	{
		data_count[0] = 0x6a09e667;
		data_count[1] = 0xbb67ae85;
		data_count[2] = 0x3c6ef372;
		data_count[3] = 0xa54ff53a;
		data_count[4] = 0x510e527f;
		data_count[5] = 0x9b05688c;
		data_count[6] = 0x1f83d9ab;
		data_count[7] = 0x5be0cd19;
		chunk = data_size = 0;
	}

	
	void Transform();
	void update(const uint8_t*, size_t);
	void update(const std::string&);
	uint8_t* digest();
	static std::string toString(const uint8_t*);
	void SHA256_Close();
	void revert(uint8_t*);
	uint32_t ROTR(uint32_t, uint32_t);
	uint32_t Choose(uint32_t, uint32_t, uint32_t);
	uint32_t Major(uint32_t, uint32_t, uint32_t);
	uint32_t sig0(uint32_t);
	uint32_t sig1(uint32_t);
	string Encyt(string);
};

#endif