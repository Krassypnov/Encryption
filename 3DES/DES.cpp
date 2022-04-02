#include "DES.h"

int64_t DES::stringToInt(const std::string& value) const
{
	int64_t bitSeq = 0;
	for (int i = 0; i < value.length(); i++)
	{
		bitSeq |= (value[i] & 0b11111111);
		if (value.length() - 1 != i)
			bitSeq <<= 8;
	}
	return bitSeq;
}

std::string DES::intToString(int64_t value) const
{
	
	std::string resultStr("00000000");
	int length = resultStr.length();
	for (int i = 0; i < length; i++)
	{
		resultStr[i] = (value & 0b11111111);
		if (i == 0)
		{
			value >>= 8;
			value = value & 0b0000000011111111111111111111111111111111111111111111111111111111;
		}
		
		
		if (i != 0)
			value >>= 8;
	}
	for (int i = 0; i < length/2; i++)
	{
		char t = resultStr[i];
		resultStr[i] = resultStr[length - i - 1];
		resultStr[length - i - 1] = t;
	}
	return resultStr;
}

int64_t DES::initPermutataion(int64_t value) const
{
	return permutateData(value, IP, 64);
}

int64_t DES::finalPermutation(int64_t value) const
{
	return permutateData(value, IP_R, 64);
}

char DES::getBit(int64_t value, char bit) const
{
	return ((value >> bit-1) & 0b1);
}

int32_t DES::getLeftPart(int64_t value) const
{
	return (value >> 32);
}

int32_t DES::getRightPart(int64_t value) const
{
	return (value & 0b11111111111111111111111111111111);
}

int32_t DES::F(int32_t value, int64_t key) const
{
	int_us B[8]{ 0 };
	int_us Bj[8]{ 0 };
	int64_t extData = 0;
	
	extData = permutateData(value, E, 48); // Extend 32 bit vector to 48 according to table E
	extData = extData ^ key; // XOR with key

	// Getting 8 blocks of 6 bits B[1..8]
	for (int i = 0; i < 8; i++)
	{
		B[i] = (extData >> i * 6) & 0b111111;
	}
	// Reverse array
	for (int i = 0; i < 4; i++)
	{
		int_us temp = B[i];
		B[i] = B[8 - i - 1];
		B[8 - i - 1] = temp;
	}
	
	// S-transform according to table S1 - S8. Getting 8 blocks of 4 bits B'[1..8] and combining them
	int64_t B_8 = 0;
	for (int i = 0; i < 8; i++)
	{
		Bj[i] = S[i][getIndexA(B[i])][getIndexB(B[i])];
		B_8 |= Bj[i];
		if (i != 7)
			B_8 <<= 4;
	}
	B_8 = permutateData(B_8, P, 32); // Permutation accordinng to table P

	return extData;
}

void DES::generateKeys(int64_t key, int64_t K[16]) const
{
	key = addByteToKey(key); // Extend key to 64 bit
	int64_t permKey = 0;
	permKey = permutateData(key, CD, 56); // Remove check bits and convert 64 bit key to 56 bit

	// Divide the 56 bit key into two parts C and D of 28 bits each
	int64_t Ci = permKey >> 28;
	int64_t Di = permKey & 0b1111111111111111111111111111;

	// Generation of 16 48 bit keys
	for (int i = 0; i < 16; i++)
	{
		// Cyclic shift C and D according to the SHIFT table
		Ci = leftShift(Ci, SHIFT[i]);
		Di = leftShift(Di, SHIFT[i]);
		
		// From two parts C and D we get a 56 bit key
		int64_t Ki = ((Ci & 0b1111111111111111111111111111) << 28) | (Di & 0b1111111111111111111111111111);

		// Using the CD_1 table, we make a 48-bit key
		K[i] = permutateData(Ki, CD_1, 48);
	}
}

int64_t DES::addByteToKey(int64_t key) const // Adding odd bytes to the key
{
	int64_t extKey = key;
	for (int i = 0; i < 8; i++)
	{
		if (bitsInByte(key & 0b11111111) % 2 == 0 && (key & 0b10000000) == 0)
		{
			extKey = insertBit(extKey, 8 * (i + 1), 1);
		}
		else if (bitsInByte(key & 0b11111111) % 2 == 0 && (key & 0b10000000) == 128)
		{
			extKey = insertBit(extKey, 8 * (i + 1), 0);
		}
		else if (bitsInByte(key & 0b11111111) % 2 != 0 && (key & 0b10000000) == 128)
		{
			extKey = insertBit(extKey, 8 * (i + 1), 1);
		}
		else
		{
			extKey = insertBit(extKey, 8 * (i + 1), 0);
		}
		key = extKey;
		key >>= 8*(i+1);
	}
	return extKey;
}

int64_t DES::insertBit(int64_t value, int bitNum, bool bitValue) const // Inserting a bit at a determine position
{
	int64_t addedValue = (value >> (bitNum-1));
	addedValue = (addedValue << 1) | bitValue;
	addedValue <<= bitNum - 1;
	value <<= (64 - bitNum + 1);
	value >>= 1;
	value &= 0b0111111111111111111111111111111111111111111111111111111111111111;
	value >>= (64 - bitNum);
	addedValue |= value;
	return addedValue;
}

int DES::bitsInByte(char byte) const // Counting the number of ones in a byte
{
	int count = 0;
	for (int i = 0; i < 8; i++)
	{
		count += byte & 0b1;
		byte >>= 1;
	}
	return count;
}

int64_t DES::leftShift(int64_t value, int shift) const // Cyclic shift to the left
{
	for (int i = 0; i < shift; i++)
	{
		int temp = ((value & 0b1000000000000000000000000000) >> 27);
		value = (value << 1) | temp;
	}
	return (value & 0b1111111111111111111111111111);
}

int64_t DES::permutateData(int64_t value, const char* table, int sizeOfTable) const // Function for permuting bits across tables
{
	int64_t permutate = 0;
	for (int i = 0; i < sizeOfTable; i++) 
	{
		permutate |= getBit(value, table[i]);
		if (i == sizeOfTable - 1)
			break;
		permutate <<= 1;
	}
	return permutate;
}

DES::int_us DES::getIndexA(int_us value) const // To get a row in S-transform
{
	return((value & 0b100000) >> 4) | (value & 0b1);
}

DES::int_us DES::getIndexB(int_us value) const // To get a column in S-transform
{
	return ((value & 0b011111) >> 1);
}

std::string DES::Encryption(const std::string& value, const std::string& keyStr) const
{
	int64_t K[16]{ 0 };
	int64_t key = stringToInt(keyStr); // Convert key from string to int64
	generateKeys(key, K); // Generation of 16 round keys of 48 bits

	int64_t DATA = stringToInt(value); // Translating source text from string to int64
	DATA = initPermutataion(DATA); // Initial Permutation

	// Divide into left and right parts of 32 bits
	int32_t L = getLeftPart(DATA);
	int32_t R = getRightPart(DATA);
	int32_t nLeft;

	// Performing 16 cycles of Feistel transformations
	for (int i = 0; i < 16; i++)
	{
		nLeft = R;
		R = L ^ F(R, K[i]);
		L = nLeft;
	}
	// We connect the converted left and right parts of 32 bits into 64
	DATA = 0;
	DATA |= (L & 0b11111111111111111111111111111111);
	DATA <<= 32;
	DATA |= (R & 0b11111111111111111111111111111111);
	
	DATA = finalPermutation(DATA); // Finite permutation

	return intToString(DATA);
}

// Decryption occurs in the same way as encryption, but in reverse order (round keys are also taken in reverse order)
std::string DES::Decryption(const std::string& value, const std::string& keyStr) const
{
	int64_t K[16]{ 0 };
	int64_t key = stringToInt(keyStr);
	generateKeys(key, K);

	int64_t DATA = stringToInt(value);
	DATA = initPermutataion(DATA);

	int64_t L = getLeftPart(DATA);
	int64_t R = getRightPart(DATA);
	int64_t nRight;

	for (int i = 0; i < 16; i++)
	{
		nRight = L;
		L = R ^ F(L, K[15-i]);
		R = nRight;
	}
	
	DATA = 0;
	DATA |= (L & 0b11111111111111111111111111111111);
	DATA <<= 32;
	DATA |= (R & 0b11111111111111111111111111111111);

	DATA = finalPermutation(DATA);

	return intToString(DATA);
}

std::string DES::getEightByteFromFile(std::fstream& file) const 
{
	char buffer[8];
	file.read(buffer, 8);
	return std::string(buffer,8);
}

int DES::getFileSize(std::fstream& file) const
{
	int fileSize = 0;
	if (file)
	{
		int curPos = file.tellg();
		file.seekg(0, std::ios_base::end);
		fileSize = file.tellg();
		file.seekg(curPos, std::ios_base::beg);
	}
	return fileSize;
}

std::string DES::addByteToStr(const std::string& value, int byteCount) const
{
	std::string addByteStr(value);
	for (int i = value.length(); i < byteCount; i++)
	{
		addByteStr += "0";
		addByteStr[i] = 0b0;
	}
	return addByteStr;
}

void DES::Log(const std::string& logMessage) const
{

	std::ofstream logFile;
	logFile.open("Log.txt", std::ios::out | std::ios::app);
	logFile << logMessage << std::endl;
	logFile.close();
}

DES::DES(const std::string& dataFilename, const std::string& outputFilename, const std::string& keyFilename, int_us mode)
{
	this->dataFilename = dataFilename;
	this->outputFilename = outputFilename;
	this->keyFilename = keyFilename;
	this->mode = mode;
}

DES::DES()
{
	this->mode = DES_DEC;
}

DES::~DES()
{
}

bool DES::isFilesNameSet() const
{
	if (!(this->dataFilename.length() == 0))
		if (!(this->outputFilename.length() == 0))
			if (!(this->keyFilename.length() == 0))
				return true;
	return false;
}

void DES::setFilesName(const std::string& dataFilename, const std::string& outputFilename, const std::string& keyFilename)
{
	this->dataFilename = dataFilename;
	this->outputFilename = outputFilename;
	this->keyFilename = keyFilename;
}

std::string DES::getDataFilename() const
{
	return this->dataFilename;
}

void DES::setEncryptionMode(int_us mode)
{
	this->mode = mode;
}

unsigned short int DES::getEncryptionMode() const
{
	return this->mode;
}

void DES::Start() const
{	
	// Initializing, opening and checking files
	if (!isFilesNameSet())
	{
		Log("Filenames not set");
		return;
	}
	std::fstream dataFile;
	std::fstream outputFile;
	std::fstream keyFile;
	dataFile.open(this->dataFilename, std::ios::binary | std::ios::in);
	if (!dataFile.is_open())
	{
		Log("Datafile is not open. Check filename or use function 'void DES::setFilesName(const std::string& dataFilename, const std::string& outputFilename, const std::string& keyFilename)'");
		return;
	}
	outputFile.open(this->outputFilename, std::ios::binary | std::ios::out);
	if (!outputFile.is_open())
	{
		Log("Output file is not open. Check filename or use function 'void DES::setFilesName(const std::string& dataFilename, const std::string& outputFilename, const std::string& keyFilename)'");
		return;
	}
	keyFile.open(this->keyFilename, std::ios::binary | std::ios::in);
	if (!keyFile.is_open())
	{
		Log("File with keys is not open. Check filename or use function 'void DES::setFilesName(const std::string& dataFilename, const std::string& outputFilename, const std::string& keyFilename)'");
		return;
	}
	
	// Determining the number of keys and writing them from a file
	std::string key;
	while (true)
	{
		char buf;
		keyFile.read(&buf, 1);
		if (keyFile.eof())
			break;
		key += buf;
	}

	int keyCount = key.length();

	if (keyCount % 7 != 0)
		keyCount = (keyCount / 7 + 1);
	else
		keyCount = keyCount / 7;

	std::string* keys = new std::string[keyCount];
	for (int i = 0; i < keyCount; i++)
	{
		if (key.length() > 7)
		{
			keys[i] = key.substr(0, 7);
			key = key.substr(7);
		}
		else
		{
			keys[i] = key;
		}
	}
	keys[keyCount - 1] = addByteToStr(keys[keyCount - 1], 7); // If the key is less than 7 bytes, then padded with null bytes

	// Main Encryption and Decryption Loop
	std::string data;
	bool isDataReady = false;
	while (true)
	{
		char buf;
		dataFile.read(&buf, 1);
		if (dataFile.eof())
		{
			if (data.length() >= 1)
				isDataReady = true;
			else
				break;
		}
		else
			data += buf;

		if (data.length() == 8)
			isDataReady = true;
		
		if (isDataReady)
		{
			// If the text length is less than 8 bytes
			if (data.length() < 8)
				data = addByteToStr(data, 8);
			//Depending on the selected mode, the file is encrypted or decrypted.
			if (this->mode)
			{
				// Depending on the n number of keys, the DES algorithm is executed n times
				for (int i = 0; i < keyCount; i++)
					data = Encryption(data, keys[i]);
				
			}
			else
			{
				for (int i = 0; i < keyCount; i++)
					data = Decryption(data, keys[keyCount - 1 - i]);
			}
			outputFile.write(data.c_str(), 8);
			data = "";
			isDataReady = false;

			if (dataFile.eof())
				break;
		}
	}
	delete[] keys;
	dataFile.close();
	outputFile.close();
	keyFile.close();
}
