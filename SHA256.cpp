#include <sstream>
#include <cstring>
#include <iomanip>
#include "SHA256.h"

const static uint32_t SHA256_K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void SHA256::update(const uint8_t* data, size_t length)
{
	for (size_t i = 0; i < length; i++)
	{
		chunk_count[chunk++] = data[i];
		if (chunk == 64)
		{
			Transform();

			data_size += 512;
			chunk = 0;
		}
	}
}

void SHA256::update(const std::string& data)
{
	update(reinterpret_cast<const uint8_t*> (data.c_str()), data.size());
}

uint8_t * SHA256::digest()
{
	uint8_t * hash = new uint8_t[32];

	SHA256_Close();
	revert(hash);

	return hash;
}

std::string SHA256::toString(const uint8_t* digest)
{
	std::stringstream s;

	s << std::setfill('0') << std::hex;

	for (uint8_t i = 0; i < 32; i++)
	{
		s << std::setw(2) << (unsigned int)digest[i];
	}

	return s.str();
}

uint32_t SHA256::ROTR(uint32_t x, uint32_t y)
{
	return (x >> y) | (x << (32 - y));
}

uint32_t SHA256::Choose(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ ((~x) & z));
}

uint32_t SHA256::Major(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

uint32_t SHA256::sig0(uint32_t x)
{
	return (ROTR(x, 7) ^ ROTR(x, 18) ^(x >> 3));
}

uint32_t SHA256::sig1(uint32_t x)
{
	return (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10));
}

void SHA256::Transform()
{
	uint32_t m[8],w[64];
	uint32_t maj, sigma1, sigma0, ch, newA, newB, sum;

	for (uint8_t i = 0, j = 0; i < 16; i++, j+= 4)
	{
		w[i] = (chunk_count[j] << 24) | (chunk_count[j + 1] << 16) | (chunk_count[j + 2] << 8) | (chunk_count[j + 3]);
	}

	for (uint8_t j = 16; j < 64; j++)
	{
		w[j]= sig1(w[j - 2]) + w[j - 7] + sig0(w[j - 15]) + w[j - 16];
	}

	for (int i = 0; i < 8; i++)
	{
		m[i] = data_count[i];
	}

	for (uint8_t i = 0; i < 64; i++)
	{
		maj = Major(m[0], m[1], m[2]);
		sigma0 = ROTR(m[0], 2) ^ ROTR(m[0], 13) ^ ROTR(m[0], 22);
		ch = Choose(m[4], m[5], m[6]);
		sigma1 = ROTR(m[4], 6) ^ ROTR(m[4], 11) ^ ROTR(m[4], 25);

		sum = w[i] + SHA256_K[i] + m[7] + ch + sigma1;
		newA = sigma0 + maj + sum;
		newB = m[3] + sum;

		m[7] = m[6];
		m[6] = m[5];
		m[5] = m[4];
		m[4] = newB;
		m[3] = m[2];
		m[2] = m[1];
		m[1] = m[0];
		m[0] = newA;
	}

	for (int i = 0; i < 8; i++)
	{
		data_count[i]+=m[i]; 
	}
}

void SHA256::SHA256_Close()
{
	uint64_t i = chunk;
	uint8_t last = (chunk < 56 ? 56 : 64);

	chunk_count[i++] = 0x80;

	while (i < last)
	{
		chunk_count[i++] = 0x00;
	}

	if (chunk >= 56)
	{
		Transform();
		memset(chunk_count, 0, 56);
	}

	data_size += chunk * 8;
	chunk_count[63] = data_size;
	chunk_count[62] = data_size >> 8;
	chunk_count[61] = data_size >> 16;
	chunk_count[60] = data_size >> 24;
	chunk_count[59] = data_size >> 32;
	chunk_count[58] = data_size >> 40;
	chunk_count[57] = data_size >> 48;
	chunk_count[56] = data_size >> 56;
	Transform();
}

void SHA256::revert(uint8_t* hash)
{
	for (uint8_t i = 0; i < 4; i++)
	{
		for (uint8_t j = 0; j < 8; j++)
		{
			hash[i + (j * 4)] = (data_count[j] >> (24 - i * 8)) & 0x000000ff;
		}
	}
}

std::string SHA256::Encyt(string Hash)
{
	SHA256 sha;
	uint8_t* temp;
	sha.update(Hash);
	temp = sha.digest();

	return (SHA256::toString(temp));
	delete[] temp;
}