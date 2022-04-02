#pragma once
#include <fstream>
#include <string>
#include <iostream>

class EGamal
{
	std::string dataFilename;
	std::string encodingTableFilename;
	std::string paramsFilename;

public:
	EGamal(const std::string& encodingTableFilename, const std::string& dataFilename, const std::string& paramsFilename);
	~EGamal();

	void Encode(const std::string& publicKeyFilename, const std::string& outputFilename) const;
	void Decode(const std::string& privateKeyFilename, const std::string& outputFilename) const;
	void generateKeys(const std::string& publicKeyFilename, const std::string& privateKeyFilename) const;
private:
	
	int NOD(int a, int b) const;
	int getRandomNumber(int leftBorder, int rightBorder) const;
	int modPow(int a, int x, int mod, int M = 1) const;
	int indexOfTheLastOne(int num) const;
	int getEncodeNum(char symbol, std::fstream& file) const;
	char getEncodeSymbol(int charCode, std::fstream& file) const;
};

