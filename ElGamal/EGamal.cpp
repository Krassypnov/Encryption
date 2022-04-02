#include "EGamal.h"



EGamal::EGamal(const std::string& encodingTableFilename, const std::string& dataFilename, const std::string& paramsFilename)
{
	srand(time(0));
	this->encodingTableFilename = encodingTableFilename;
	this->dataFilename = dataFilename;
	this->paramsFilename = paramsFilename;
}

EGamal::~EGamal()
{
}

void EGamal::Encode(const std::string& publicKeyFilename, const std::string& outputFilename) const
{
	std::fstream dataFile(this->dataFilename, std::ios::in);
	if (!dataFile.is_open())
	{
		std::cerr << "Unbale to open data file\n";
		return;
	}

	std::fstream encodeFile(this->encodingTableFilename, std::ios::in);
	if (!encodeFile.is_open())
	{
		std::cerr << "Unbale to open encoding file\n";
		return;
	}

	std::fstream keyFile(publicKeyFilename, std::ios::binary | std::ios::in);
	if (!keyFile.is_open())
	{
		std::cerr << "Unbale to open parameter file\n";
		return;
	}

	std::fstream outputFile(outputFilename, std::ios::binary | std::ios::out);
	if (!outputFile.is_open())
	{
		std::cerr << "Output file not created\n";
		return;
	}

	int y;
	int p;
	int g;

	keyFile.read((char*)&y, sizeof(y));
	keyFile.read((char*)&p, sizeof(p));
	keyFile.read((char*)&g, sizeof(g));

	keyFile.close();

	int k;
	for (k = p - 2; k > 0; k--)
		if (NOD(k, (p - 1))) break;

	int a = modPow(g, k, p);
	while (true)
	{
		char symbol;
		dataFile.read(&symbol, 1);
		if (dataFile.eof())
			break;

		symbol = getEncodeNum(symbol, encodeFile);
		int b = modPow(y, k, p, (int)symbol);

		outputFile.write((char*)&a, sizeof(a));
		outputFile.write((char*)&b, sizeof(b));
	}
}

void EGamal::Decode(const std::string& privateKeyFilename, const std::string& outputFilename) const
{
	std::fstream dataFile(this->dataFilename, std::ios::binary | std::ios::in);
	if (!dataFile.is_open())
	{
		std::cerr << "Unbale to open data file\n";
		return;
	}

	std::fstream encodeFile(this->encodingTableFilename, std::ios::in);
	if (!encodeFile.is_open())
	{
		std::cerr << "Unbale to open encoding file\n";
		return;
	}

	std::fstream keyFile(privateKeyFilename, std::ios::binary | std::ios::in);
	if (!keyFile.is_open())
	{
		std::cerr << "Unbale to open parameter file\n";
		return;
	}

	std::fstream outputFile(outputFilename, std::ios::binary | std::ios::out);
	if (!outputFile.is_open())
	{
		std::cerr << "Output file not created\n";
		return;
	}

	int x;
	int p;

	keyFile.read((char*)&x, sizeof(x));
	keyFile.read((char*)&p, sizeof(p));
	keyFile.close();

	int a;
	int b;
	
	while (true)
	{
		dataFile.read((char*)&a, sizeof(a));
		dataFile.read((char*)&b, sizeof(b));
		if (dataFile.eof())
			break;

		int M = modPow(a, p - 1 - x, p, b);
		char symbol = getEncodeSymbol(M, encodeFile);
		outputFile.write(&symbol, 1);
	}
}

void EGamal::generateKeys(const std::string& publicKeyFilename, const std::string& privateKeyFilename) const
{
	std::fstream paramFile(this->paramsFilename, std::ios::in);
	if (!paramFile.is_open())
	{
		std::cerr << "Unable to open parameter file\n";
		return;
	}
	std::string data;
	std::getline(paramFile, data);
	if (data.empty())
	{
		std::cerr << "Parameter file is empty\n";
		return;
	}

	int8_t separator = data.find(' ');
	int p = std::stoi(data.substr(0, separator));
	int g = std::stoi(data.substr(separator));

	int x = getRandomNumber(1, p - 1);
	int y = modPow(g, x, p);
	
	
	std::fstream publicKeyFile(publicKeyFilename, std::ios::binary | std::ios::out);
	if (!publicKeyFile.is_open())
	{
		std::cerr << "Public key file not created\n";
		return;
	}

	publicKeyFile.write((char*)&y, sizeof(y));
	publicKeyFile.write((char*)&p, sizeof(p));
	publicKeyFile.write((char*)&g, sizeof(g));

	publicKeyFile.close();

	std::fstream privateKeyFile(privateKeyFilename, std::ios::binary | std::ios::out);
	if (!privateKeyFile.is_open())
	{
		std::cerr << "Private key file not created\n";
		return;
	}

	privateKeyFile.write((char*)&x, sizeof(x));
	privateKeyFile.write((char*)&p, sizeof(g));
	privateKeyFile.close();
}

int EGamal::NOD(int a, int b) const
{
	while (a > 0 && b > 0)
	{
		if (a > b)
			a = a % b;
		else
			b = b % a;
	}
	return a + b;
}

int EGamal::getRandomNumber(int leftBorder, int rightBorder) const
{
	return rand() % (rightBorder - leftBorder - 1) + leftBorder;
}

int EGamal::modPow(int a, int x, int mod, int M) const
{
	int64_t y = 1*M;
	int64_t s = a;
	int index = indexOfTheLastOne(x) + 1;

	for (int i = 0; i < index; i++)
	{
		if ((x & 0b1) == 1)
			y = (y * s) % mod;
		s = (s * s) % mod;
		x >>= 1;
	}
	return y;
}

int EGamal::indexOfTheLastOne(int num) const
{
	int index = 0;
	for (int i = 0; i < 32; i++)
	{
		if ((num & 0b1) == 1)
			index = i;
		num >>= 1;
	}
	return index;
}

int EGamal::getEncodeNum(char symbol, std::fstream& file) const
{
	file.clear();
	file.seekg(0);
	std::string line;
	char sym;
	while (true)
	{
		file.read(&sym, 1);
		if (file.eof())
			break;

		line += sym;
		if (line.length() == 5)
		{
			line = line.substr(0, 4);
			int separator = line.find(':') + 1;
			if (line.substr(0, separator)[0] == symbol)
			{
				int charCode = std::stoi(line.substr(separator));
				return charCode;
			}
			line = "";
		}
	}
	return -1;
}

char EGamal::getEncodeSymbol(int charCode, std::fstream& file) const
{
	file.clear();
	file.seekg(0);
	std::string line;
	while (true)
	{
		char symbol;
		file.read(&symbol, 1);

		if (file.eof())
			break;
		line += symbol;
		if (line.length() == 5)
		{
			line = line.substr(0, 4);
			int separator = line.find(':')+1;
			if (abs(stoi(line.substr(separator))) == charCode)
			{
				char encodeSymbol;
				encodeSymbol = line.substr(0, separator)[0];
				return encodeSymbol;
			}
			line = "";
		}
	}
	return -1;
}
