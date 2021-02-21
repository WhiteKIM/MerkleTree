/*
* @ Make Simple MerkleTree
* @ 2020.02.21 - WhiteKIM
*/

#include <cstdint>
#include <cstring>
#include <cmath>
#include "SHA256.h"
#include <string>

#ifndef MERKLETREE_H
#define MERKLETREE_H

using namespace std;

/*
* @ Param String
* @ return String array
*/
string* MakeTree(string item)
{
	int length = item.length();
	int height = length;
	SHA256 sha;
	string *arr = new string[pow(2, height)-1];
	string left, right;
	arr[0] = ""; //Dont insert Data
	arr[1] = item; // Root Node start

	for (int i = 1; i < length; i++)
	{
		left = arr[i].substr(0, length / 2);
		right = arr[i].substr(length / 2 + 1);

		left = sha.Encyt(left);
		right = sha.Encyt(right);

		arr[(i*2)] = left;
		arr[(i*2)+1] = right;
	}

	return arr;
}

void PrintAll(string* item)
{
	int i = 1;
	while (item[i]!="")
	{
		cout << item[i] << " -> ";
		i++;
	}
}

#endif