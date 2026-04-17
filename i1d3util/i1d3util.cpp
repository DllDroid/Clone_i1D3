
/* 
 * i1D3util.cpp
 *
 * Utility program for X-Rite i1d3 probes
 *
 * Date:   1/1/2020 (refactored for cross-platform support 2026)
 *
 * This material is licenced under the GNU GENERAL PUBLIC LICENSE Version 2 or later :-
 * see the ../License file for licencing details.
 * 
 * 
 */


// Notes:
// 
// This work is shared AS IS.  You use it at your own risk.  It is possible, though unlikely that you could damage your probe if used.
//
// This work was inspired in part by the driver code from Argyll color management system
// full credit is given to Argyll?s author for any code similarities.
// https://www.argyllcms.com/
//
// Additional information was obtained by the use of the protocol analysis tool Wireshark
// https://www.wireshark.org/
// 
// Further information was obtained by extracting the firmware from i1d3 using PICKIT2 tools from Microchip and analysing it with Ghidra
// https://ghidra-sre.org/
//
// As a note, no Windows DLLs were analysed in order to create i1d3util.  It was just not required!
//
//
//
//
//
// The i1d3 has both internal and external EEPROMs.  The internal EEPROM contains the serial number, the external EEPROM contains the unique
// device sensor calibration data and the ?signature? that determines which flavour of i1d3 it is locked to (oem, retail, colormunki,C6 etc.)
// 
// The command i1d3util -? will give a help screen
//
// The i1d3util tool has a number of command line options, both in lowercase and uppercase.  Lowercase are read commands, uppercase are write commands.  
// The i1d3util tool can read the data out of the id3 and write it to disk, it can also take data on disk and write it back into the i1d3.  
// By doing this, you can backup and restore your probe.
//
// The i1d3util tool can access both internal and external EEPROM data.  It can also specifically access/change the serial number and signature data.
//
// For example, if you have a retail probe and the signature data from an oem probe, you can load the oem signature into the retail probe.  
// The probe will now operate as if it were a factory oem probe.
//
// The -f option enables you to overwrite (without warning!!) a file on disk.
// The -w option enables ACTUAL writing to the i1d3 EEPROMs!
// The -v reads the firmware revision from the i1d3 hardware
// 
// Example command to load a oem probe signiture file into ANY i1d3 probe:
// 
// i1d3util -w -S oem1D3signature.bin
//
//
// It is STRONGLY RECOMMENDED that you save you probes current internal EEPROM data, external EEPROM data, 
// signature data and serial number before you start changing anything
//
// Be VERY careful to write the correct data file to the correct section of the probe!!
//
// It is possible to corrupt the internal EEPROM.  If this happens, the i1d3 reports back a different USB Vendor ID.  
// The i1d3util will try and detect this and correct the problem.
//
// Between each WRITE to the i1d3, it is important that you unplug and plug back in the probe to reset the Windows device driver.
//
// Once a write operation has been performed, the i1d3 sometimes starts flashing its white LEDS.  This is normal, and is part of it visual feedback system.  
// Most application will either turn this off or allow you to turn it off/on
//
// Have fun!


#include <stdio.h>
#include <stdlib.h>

#include <math.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <hidapi.h>


using namespace std;

int optind(1), optopt;
const char* optarg;

#define BADCH   (int)'?'
#define BADARG  (int)':'
static const char EMSG[] = "";

int getopt(int nargc, char * const nargv[], const char *ostr)
{
	static const char *place = EMSG;        /* option letter processing */
	const char *oli;                        /* option letter list index */

	if(!*place)
	{
		if(optind >= nargc || *(place = nargv[optind]) != '-')
		{
			place = EMSG;
			return -1;
		}

		if(place[1] && *++place == '-')
		{
			++optind;
			place = EMSG;
			return -1;
		}
	}

	if((optopt = (int)*place++) == (int)':' || !(oli = strchr(ostr, optopt)))
	{
		if(optopt == (int)'-')  return -1;
		if(!*place) ++optind;
		return BADCH;
	}

	if(*++oli != ':')
	{
		optarg = NULL;
		if(!*place) ++optind;
	}
	else
	{
		if(*place) optarg = place;
		else if (nargc <= ++optind)
		{
			place = EMSG;
			if(*ostr == ':') return (BADARG);
			return (BADCH);
		}
		else optarg = nargv[optind];
		place = EMSG;
		++optind;
	}

	return optopt;
}

class hidIdevice
{
	public:
					hidIdevice():dpath(0), fh(0) {};
				   ~hidIdevice(){ if(dpath) delete[] dpath;};

	char*			dpath;
	hid_device*		fh;
	unsigned int	ProductID;
};

int loadDLLfuncs()
{
	return (hid_init() == 0) ? 1 : 0;
}


hidIdevice* findHIDdevice()
{
	hidIdevice* hidDev(0);
	hid_device_info* devs = hid_enumerate(0x0, 0x0);
	hid_device_info* cur = devs;

	while(cur)
	{
		unsigned int vendorID = cur->vendor_id;
		unsigned int productID = cur->product_id;
		if((vendorID == 0x0765) && ((productID == 0x5020) || (productID == 0x5021)))
		{
			hidDev = new hidIdevice;
			if(!hidDev) return 0;
			hidDev->dpath = new char[strlen(cur->path) + 1];
			if(!hidDev->dpath) return 0;
			memset(hidDev->dpath, 0x00, strlen(cur->path) + 1);
			strcpy(hidDev->dpath, cur->path);

			hidDev->ProductID = productID;

			break;
		}
		cur = cur->next;
	}
	hid_free_enumeration(devs);

    return hidDev;
}


bool openHIDdevice(hidIdevice* dev)
{
	if(dev == NULL || dev->dpath == NULL) return false;
	dev->fh = hid_open_path(dev->dpath);
	return (dev->fh != NULL);
}

int i1d3ReadExternalEeprom(hidIdevice* dev, unsigned char* buf);
int i1d3ReadInternalEeprom(hidIdevice* dev, unsigned char* buf);


void closeHIDdevice(hidIdevice* dev)
{
	if(dev == NULL) return;
	if(dev->fh) hid_close(dev->fh);
	delete dev;
}


int	readHIDdevice(hidIdevice* dev, unsigned char* rbuf,	int numToRead, double timeout)
{
	if(dev == NULL || dev->fh == NULL) return -1;

	unsigned char* lBuf;
	lBuf = new unsigned char[numToRead + 1];
	if(!lBuf) return -1;
	memset(lBuf, 0x00, numToRead + 1);

	int numRead = hid_read_timeout(dev->fh, lBuf, numToRead + 1, (int)(timeout * 1000.0 + 0.5));

	if(numRead > 0)
	{
		/*
		 * Different HID backends return input reports differently:
		 * - some include a leading report-id byte (often 0x00),
		 * - others return payload bytes only.
		 * Handle both to keep protocol framing stable across OSes.
		 */
		if(numRead == (numToRead + 1))
		{
			numRead--;
			memcpy(rbuf, lBuf + 1, numRead);
		}
		else
		{
			if(numRead > numToRead) numRead = numToRead;
			memcpy(rbuf, lBuf, numRead);
		}
	}

	delete[] lBuf;

	return numRead;
}


int writeHIDdevice(hidIdevice* dev,	unsigned char* wbuf, int numToWrite, double timeout = 1.0)
{
	if(dev == NULL || dev->fh == NULL) return -1;

	unsigned char* lBuf;
	lBuf = new unsigned char[numToWrite + 1];
	if(!lBuf) return -1;
	memset(lBuf, 0x00, numToWrite + 1);
	memcpy(lBuf + 1, wbuf, numToWrite);

	(void)timeout;
	int numWritten = hid_write(dev->fh, lBuf, numToWrite + 1);

	if(numWritten > 0)
	{
		numWritten--;
	}

	delete[] lBuf;

	return numWritten;
}

bool writeFileBytes(const char* fileName, const unsigned char* buf, size_t len, bool forceOverwrite)
{
	if(!forceOverwrite)
	{
		FILE* check = fopen(fileName, "rb");
		if(check)
		{
			fclose(check);
			return false;
		}
	}

	FILE* f = fopen(fileName, "wb");
	if(!f) return false;

	size_t written = fwrite(buf, 1, len, f);
	fclose(f);
	return (written == len);
}

bool readFileBytes(const char* fileName, unsigned char* buf, size_t len)
{
	FILE* f = fopen(fileName, "rb");
	if(!f) return false;

	size_t noRead = fread(buf, 1, len, f);
	fclose(f);
	return (noRead == len);
}

bool validateFileSize(const char* fileName, size_t expectedSize)
{
	FILE* f = fopen(fileName, "rb");
	if(!f) return false;

	if(fseek(f, 0, SEEK_END) != 0)
	{
		fclose(f);
		return false;
	}

	long sz = ftell(f);
	fclose(f);
	if(sz < 0) return false;

	return ((size_t)sz == expectedSize);
}

bool verifyFileMatches(const char* fileName, const unsigned char* expected, size_t len)
{
	unsigned char* verifyBuf = new unsigned char[len];
	if(!verifyBuf) return false;

	bool ok = readFileBytes(fileName, verifyBuf, len);
	if(ok) ok = (memcmp(verifyBuf, expected, len) == 0);

	delete[] verifyBuf;
	return ok;
}

static inline uint32_t sha256_rotr(uint32_t v, uint32_t n)
{
	return (v >> n) | (v << (32 - n));
}

void sha256Bytes(const unsigned char* data, size_t len, unsigned char out[32])
{
	static const uint32_t k[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	uint32_t h[8] = {
		0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
	};

	size_t newLen = len + 1;
	while((newLen % 64) != 56) ++newLen;
	unsigned char* msg = new unsigned char[newLen + 8];
	memset(msg, 0x00, newLen + 8);
	memcpy(msg, data, len);
	msg[len] = 0x80;
	uint64_t bitLen = (uint64_t)len * 8ULL;
	for(int i = 0; i < 8; ++i) msg[newLen + 7 - i] = (unsigned char)((bitLen >> (i * 8)) & 0xff);

	for(size_t off = 0; off < newLen + 8; off += 64)
	{
		uint32_t w[64];
		for(int i = 0; i < 16; ++i)
		{
			size_t j = off + (size_t)i * 4;
			w[i] = ((uint32_t)msg[j] << 24) | ((uint32_t)msg[j + 1] << 16) | ((uint32_t)msg[j + 2] << 8) | (uint32_t)msg[j + 3];
		}
		for(int i = 16; i < 64; ++i)
		{
			uint32_t s0 = sha256_rotr(w[i - 15], 7) ^ sha256_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
			uint32_t s1 = sha256_rotr(w[i - 2], 17) ^ sha256_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], x = h[7];
		for(int i = 0; i < 64; ++i)
		{
			uint32_t S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
			uint32_t ch = (e & f) ^ (~e & g);
			uint32_t temp1 = x + S1 + ch + k[i] + w[i];
			uint32_t S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = S0 + maj;

			x = g; g = f; f = e; e = d + temp1;
			d = c; c = b; b = a; a = temp1 + temp2;
		}

		h[0] += a; h[1] += b; h[2] += c; h[3] += d;
		h[4] += e; h[5] += f; h[6] += g; h[7] += x;
	}

	delete[] msg;

	for(int i = 0; i < 8; ++i)
	{
		out[i * 4 + 0] = (unsigned char)((h[i] >> 24) & 0xff);
		out[i * 4 + 1] = (unsigned char)((h[i] >> 16) & 0xff);
		out[i * 4 + 2] = (unsigned char)((h[i] >> 8) & 0xff);
		out[i * 4 + 3] = (unsigned char)(h[i] & 0xff);
	}
}

bool isBlockedRetailSignature(const unsigned char* sigBuf, size_t sigLen)
{
	static const unsigned char blockedSha256[32] = {
		0x3a,0xd0,0xb3,0x90,0x75,0xea,0xa4,0xb9,0xfe,0xa6,0x65,0x7f,0xe2,0x8f,0x46,0xdd,
		0x6a,0x44,0xd8,0xd4,0x49,0xb3,0x8f,0xbc,0x35,0x4e,0x05,0x51,0x74,0xcd,0xb1,0xaa
	};
	if(sigLen != 0x48) return false;

	unsigned char digest[32];
	sha256Bytes(sigBuf, sigLen, digest);
	return (memcmp(digest, blockedSha256, 32) == 0);
}

bool readInternalEepromStable(hidIdevice* dev, unsigned char* outBuf)
{
	unsigned char* r1 = new unsigned char[256];
	unsigned char* r2 = new unsigned char[256];
	unsigned char* r3 = new unsigned char[256];
	if(!r1 || !r2 || !r3)
	{
		if(r1) delete[] r1;
		if(r2) delete[] r2;
		if(r3) delete[] r3;
		return false;
	}

	memset(r1, 0x00, 256);
	memset(r2, 0x00, 256);
	memset(r3, 0x00, 256);

	i1d3ReadInternalEeprom(dev, r1);
	i1d3ReadInternalEeprom(dev, r2);
	i1d3ReadInternalEeprom(dev, r3);

	bool match = (memcmp(r1, r2, 256) == 0) && (memcmp(r1, r3, 256) == 0);
	if(match) memcpy(outBuf, r1, 256);

	delete[] r1;
	delete[] r2;
	delete[] r3;
	return match;
}

bool readExternalEepromStable(hidIdevice* dev, unsigned char* outBuf)
{
	unsigned char* r1 = new unsigned char[8192];
	unsigned char* r2 = new unsigned char[8192];
	unsigned char* r3 = new unsigned char[8192];
	if(!r1 || !r2 || !r3)
	{
		if(r1) delete[] r1;
		if(r2) delete[] r2;
		if(r3) delete[] r3;
		return false;
	}

	memset(r1, 0x00, 8192);
	memset(r2, 0x00, 8192);
	memset(r3, 0x00, 8192);

	i1d3ReadExternalEeprom(dev, r1);
	i1d3ReadExternalEeprom(dev, r2);
	i1d3ReadExternalEeprom(dev, r3);

	bool match = (memcmp(r1, r2, 8192) == 0) && (memcmp(r1, r3, 8192) == 0);
	if(match) memcpy(outBuf, r1, 8192);

	delete[] r1;
	delete[] r2;
	delete[] r3;
	return match;
}


int i1d3Command(hidIdevice* dev,unsigned short cmdCode, unsigned char* sBuf, unsigned char* rBuf, double timeout = 1.0)
{
	unsigned char cmd;		/* Major command code */
	int wbytes;				/* bytes written */
	int rbytes;				/* bytes read from ep */
	int num;

	cmd = (cmdCode >> 8) & 0xff;	// Major command == HID report number
	sBuf[0] = cmd;

	if(cmd == 0x00) sBuf[1] = (cmdCode & 0xff);	// Minor command

	num = writeHIDdevice(dev, sBuf, 64, timeout);
	if(num == -1)
	{
		// flush any crap
		num = readHIDdevice(dev, rBuf, 64, timeout);
		return -1;
	}

	num = readHIDdevice(dev, rBuf, 64, timeout);
	if(num == -1)
	{
		// flush any crap
		num = readHIDdevice(dev, rBuf, 64, timeout);
		return -1;
	}

	/* The first byte returned seems to be a command result error code. */
	if((rBuf[0] != 0x00) || (rBuf[1] != cmd))
	{
		return -1;
	}

	return 0; 
}


void i1d3GetInfo(hidIdevice* dev, char* rBuf)
{
	unsigned char tBuf[64];
	unsigned char fBuf[64];
	unsigned short cmd;

	memset(tBuf, 0, 64);
	memset(fBuf, 0, 64);

	cmd = 0x0000;
	i1d3Command(dev, cmd, tBuf, fBuf);
	
	strncpy((char *)rBuf, (char *)fBuf + 2, 62);
}


int i1d3ReadExternalEeprom(hidIdevice* dev,	unsigned char* buf)
{
	unsigned char tBuf[64];
	unsigned char fBuf[64];
	unsigned short cmd;

	memset(tBuf, 0, 64);
	memset(fBuf, 0, 64);

	cmd = 0x1200;

	unsigned char* bPtr = buf;

	// read up into 59 byte packets
	unsigned short addr(0);
	for(int len(8192), inc(0); len > 0; addr += inc, bPtr += inc, len -= inc)
	{
		inc = len;
		if(inc > 59) inc = 59;

		tBuf[1]	= (addr >> 8) & 0xff;
		tBuf[2] = addr & 0xff;
		tBuf[3] = (unsigned char)inc;

		i1d3Command(dev, cmd, tBuf, fBuf);
	
		memcpy(bPtr, fBuf + 5, inc);
	}

	return 0;
}


int i1d3WriteExternalEeprom(hidIdevice* dev,	unsigned char* buf)
{
	unsigned char tBuf[64];
	unsigned char fBuf[64];
	unsigned short cmd;

	memset(tBuf, 0, 64);
	memset(fBuf, 0, 64);

	cmd = 0x1300;

	unsigned char* bPtr = buf;

	// write up into 59 byte packets
	unsigned short addr(0);
	for(int len(8192), inc(0); len > 0; addr += inc, bPtr += inc, len -= inc)
	{
		inc = len;
		if(inc > 32) inc = 32;

		tBuf[1]	= (addr >> 8) & 0xff;
		tBuf[2] = addr & 0xff;
		tBuf[3] = (unsigned char)inc;

		memcpy(tBuf + 4, bPtr, inc);
	
		i1d3Command(dev, cmd, tBuf, fBuf);
	}

	return 0;
}


int i1d3ReadInternalEeprom(hidIdevice* dev,	unsigned char* buf)
{
	unsigned char tBuf[64];
	unsigned char fBuf[64];
	unsigned short cmd;

	memset(tBuf, 0, 64);
	memset(fBuf, 0, 64);

	cmd = 0x0800;

	unsigned char* bPtr = buf;

	// read up into 60 byte packets
	unsigned short addr(0);
	for(int len(256), inc(0); len > 0; addr += inc, bPtr += inc, len -= inc)
	{
		inc = len;
		if(inc > 60) inc = 60;

		tBuf[1]	= addr;
		tBuf[2] = (unsigned char)inc;

		i1d3Command(dev, cmd, tBuf, fBuf);
	
		memcpy(bPtr, fBuf + 4, inc);
	}

	return 0;
}


int i1d3WriteInternalEeprom(hidIdevice* dev,	unsigned char* buf)
{
	unsigned char tBuf[64];
	unsigned char fBuf[64];
	unsigned short cmd;

	memset(tBuf, 0, 64);
	memset(fBuf, 0, 64);

	cmd = 0x0700;

	unsigned char* bPtr = buf;

	// write up into 32 byte packets
	unsigned short addr(0);
	for(int len(256), inc(0); len > 0; addr += inc, bPtr += inc, len -= inc)
	{
		inc = len;
		if(inc > 32) inc = 32;

		tBuf[1]	= addr;
		tBuf[2] = (unsigned char)inc;
	
		memcpy(tBuf + 3, bPtr, inc);

		i1d3Command(dev, cmd, tBuf, fBuf);
	}

	return 0;
}

void i1d3CreateUnLockResponse(unsigned int k0, unsigned int k1, unsigned char* c, unsigned char* r)
{
//static void create_unlock_response(unsigned int *k, unsigned char *c, unsigned char *r) {

	int i;
	unsigned char sc[8], sr[16];	/* Sub-challeng and response */

	/* Only 8 bytes is used out of challenge buffer starting at */
	/* offset 35. Bytes are decoded with xor of byte 3 value. */
	for (i = 0; i < 8; i++)
		sc[i] = c[3] ^ c[35 + i];
	
	/* Combine 8 byte key with 16 byte challenge to create core 16 byte response */
	{
		unsigned int ci[2];		/* challenge as 4 ints */
		unsigned int co[4];		/* product, difference of 4 ints */
		unsigned int sum;		/* Sum of all input bytes */
		unsigned char s0, s1;	/* Byte components of sum. */

		/* Shuffle bytes into 32 bit ints to be able to use 32 bit computation. */
		ci[0] = (sc[3] << 24)
              + (sc[0] << 16)
              + (sc[4] << 8)
              + (sc[6]);

		ci[1] = (sc[1] << 24)
              + (sc[7] << 16)
              + (sc[2] << 8)
              + (sc[5]);
	
		/* Computation on the ints */
		co[0] = -k0 - ci[1];
		co[1] = -k1 - ci[0];
		co[2] = ci[1] * -k0;
		co[3] = ci[0] * -k1;
	
		/* Sum of challenge bytes */
		for (sum = 0, i = 0; i < 8; i++)
			sum += sc[i];

		/* Minus the two key values as bytes */
		sum += (0xff & -k0) + (0xff & (-k0 >> 8))
	        +  (0xff & (-k0 >> 16)) + (0xff & (-k0 >> 24));
		sum += (0xff & -k1) + (0xff & (-k1 >> 8))
	        +  (0xff & (-k1 >> 16)) + (0xff & (-k1 >> 24));
	
		/* Convert sum to bytes. Only need 2, because sum of 16 bytes can't exceed 16 bits. */
		s0 =  sum       & 0xff;
		s1 = (sum >> 8) & 0xff;
	
		/* Final computation of 16 bytes from 4 ints + sum bytes */
		sr[0] =  ((co[0] >> 16) & 0xff) + s0;
		sr[1] =  ((co[2] >>  8) & 0xff) - s1;
		sr[2] =  ( co[3]        & 0xff) + s1;
		sr[3] =  ((co[1] >> 16) & 0xff) + s0;
		sr[4] =  ((co[2] >> 16) & 0xff) - s1;
		sr[5] =  ((co[3] >> 16) & 0xff) - s0;
		sr[6] =  ((co[1] >> 24) & 0xff) - s0;
		sr[7] =  ( co[0]        & 0xff) - s1;
		sr[8] =  ((co[3] >>  8) & 0xff) + s0;
		sr[9] =  ((co[2] >> 24) & 0xff) - s1;
		sr[10] = ((co[0] >>  8) & 0xff) + s0;
		sr[11] = ((co[1] >>  8) & 0xff) - s1;
		sr[12] = ( co[1]        & 0xff) + s1;
		sr[13] = ((co[3] >> 24) & 0xff) + s1;
		sr[14] = ( co[2]        & 0xff) + s0;
		sr[15] = ((co[0] >> 24) & 0xff) - s0;
	}

	/* The OEM driver sets the resonse to random bytes, */
	/* but we don't need to do this, since the device doesn't */
	/* look at them. We could add random bytes if an instrument */
	/* update were to reject zero bytes. */
	for (i = 0; i < 64; i++)
		r[i] = 0;

	/* The actual resonse is 16 bytes at offset 24 in the response buffer. */
	/* The OEM driver xor's challenge byte 2 with response bytes 4..63, but */
	/* since the instrument doesn't look at them, we only do this to the actual */
	/* response. */
	for (i = 0; i < 16; i++)
		r[24 + i] = c[2] ^ sr[i];
}


 unsigned int i1d3UnLockKeys[][2] = {
	{ 0xe9622e9f, 0x8d63e133 },
	{ 0xe01e6e0a, 0x257462de },
	{ 0xcaa62b2c, 0x30815b61 }, //oem
	{ 0xa9119479, 0x5b168761 },
	{ 0x160eb6ae, 0x14440e70 },
	{ 0x291e41d7, 0x51937bdd },
	{ 0x1abfae03, 0xf25ac8e8 },
	{ 0xc9bfafe0, 0x02871166 }, //c6
	{ 0x828c43e9, 0xcbb8a8ed }
};

int i1d3numUnLockKeys(9);


int i1d3UnLock(hidIdevice* dev)
{
	unsigned char tBuf[64];
	unsigned char fBuf[64];
	unsigned short cmd;


	for(int cc(0); cc < i1d3numUnLockKeys; ++cc)
	{
		memset(tBuf, 0, 64);
		memset(fBuf, 0, 64);

		// Send the challenge
		cmd = 0x9900;
		if(i1d3Command(dev, cmd, tBuf, fBuf) < 0) continue;

		// Convert challenge to response
		i1d3CreateUnLockResponse(i1d3UnLockKeys[cc][0], i1d3UnLockKeys[cc][1], fBuf, tBuf);

		// Send the response
		cmd = 0x9a00;
		if(i1d3Command(dev, cmd, tBuf, fBuf) < 0) continue;

		if(fBuf[2] == 0x77)
		{
			/* Check success */
			return cc;
		}
	}

	return -1;
}


int i1d3EnWrite(hidIdevice* dev)
{
	unsigned char tBuf[64];
	unsigned char fBuf[64];
	unsigned short cmd;


	memset(tBuf, 0, 64);
	memset(fBuf, 0, 64);

	// Send the challenge
	cmd = 0xab00;

	tBuf[1]	= 0xa3;
	tBuf[2]	= 0x80;
	tBuf[3]	= 0x25;
	tBuf[4]	= 0x41;

	if(i1d3Command(dev, cmd, tBuf, fBuf) < 0) return -1;
	return 0;
}

unsigned int calcCsum(unsigned char* buf, bool alt = false)
{
	unsigned int sum(0);
	unsigned int sz(0x178e);  // rev2
	if(alt) sz = 0x179a;	  // rev1

	for(int i(4); i < sz; i++)
	{
		sum += buf[i];
	}
	sum &= 0xffff;

	return sum;
}


//extern const char *optarg;
//extern int optind, opterr, optopt;

int main(int argc, char **argv)
{
	cout << "i1d3util ver 1.1" << endl;


    char* fileName(0);
	bool verNum(false);
	bool forceOverWrite(false);
	bool enableEEPROMwrite(false);

	bool rSerNum(false);
	bool wSerNum(false);
	bool rIeeprom(false);
	bool wIeeprom(false);
	bool rEeeprom(false);
	bool wEeeprom(false);
	bool rSig(false);
	bool wSig(false);
	bool rAll(false);

    int   opt(0);
    while(1)
    {
        opt = getopt(argc, argv, "fwavnNiIeEsS");
        
        if(opt == -1) break;
                
        switch(opt)
        {
            case 'f':
            {
                forceOverWrite = true;
            }
            break;
            
            case 'w':
            {
                enableEEPROMwrite = true;
            }
            break;

            case 'v':
            {
				verNum = true;
            }
            break;
            
            case 'n':
            {
				rSerNum = true;
            }
            break;
            
            case 'N':
            {
				wSerNum = true;
            }
            break;
            
            case 'i':
            {
				rIeeprom = true;
            }
            break;
            
            case 'I':
            {
				wIeeprom = true;
            }
            break;
            
            case 'e':
            {
				rEeeprom = true;
            }
            break;
            
            case 'E':
            {
				wEeeprom = true;
            }
            break;
            
            case 's':
            {
				rSig = true;
            }
            break;

            case 'a':
            {
				rAll = true;
            }
            break;
            
            case 'S':
            {
				wSig = true;
            }
            break;
            
            case '?':
            {
 	        cout																			<< endl;
	        cout << "i1d3util <options> <filename>"											<< endl;
	        cout																			<< endl;
            cout << " -v              read the i1d3 firmware version information"			<< endl;
	        cout																			<< endl;
            cout << " -n              read the i1d3 serial number"							<< endl;
            cout << " -N              write the i1d3 serial number"							<< endl;
	        cout																			<< endl;
            cout << " -i              read the internal EEPROM and write it to a file"		<< endl;
            cout << " -I              read a file and load it into the internal EEPROM"		<< endl;
	        cout																			<< endl;
            cout << " -e              read the external EEPROM and write it to a file"		<< endl;
            cout << " -E              read a file and load it into the external EEPROM"		<< endl;
	        cout																			<< endl;
            cout << " -s              read external EEPROM signature and write to a file"	<< endl;
            cout << " -S              read a signature file and update the external EEPROM"	<< endl;
	        cout																			<< endl;
            cout << " -a              read all EEPROM data and auto-save by serial number"	<< endl;
	        cout																			<< endl;
            cout << " -f              force file overwrite"									<< endl;
            cout << " -w              enable EEPROM writing"									<< endl;
	        exit(1);
            }
            break;
            
            default:
            {
                cout << "Error: bad option" << endl;
                exit(1);
            }
        }
    }
    
    if(optind < argc)
    {
        fileName = new char[strlen(argv[optind]) + 1];
		strcpy(fileName, argv[optind]);
    }
	else if(rIeeprom || wIeeprom || rEeeprom || wEeeprom || rSig || wSig)
	{
		cout << "Error: missing filename" << endl;
		exit(1);
	}

	if(rAll && fileName)
	{
		if(fileName) delete[] fileName;
		cout << "Error: -a does not take a filename argument" << endl;
		exit(1);
	}

	if(rAll && (verNum || rSerNum || wSerNum || rIeeprom || wIeeprom || rEeeprom || wEeeprom || rSig || wSig))
	{
		if(fileName) delete[] fileName;
		cout << "Error: -a cannot be combined with other read/write action flags" << endl;
		exit(1);
	}
	
	if(wSerNum && !fileName)
	{
		cout << "Error: missing serial number" << endl;
		exit(1);
	}

	bool writeOp = (wSerNum || wIeeprom || wEeeprom || wSig);
	if(writeOp && !enableEEPROMwrite)
	{
		cout << "Error: refusing write operation without -w" << endl;
		exit(1);
	}

    if(!fileName && !verNum && !rSerNum && !wSerNum && !rIeeprom && !wIeeprom && !rEeeprom && !wEeeprom && !rSig && !wSig && !rAll)
	{
        cout << "i1d3util -? for help" << endl;
	}


 	if(loadDLLfuncs() == 0)// load the DLL functions
	{
        cout << "Error: failed to load USB DLL functions" << endl;
        exit(1);
	}

	hidIdevice* hidDev = findHIDdevice();
	if(!hidDev)
	{
        cout << "Error: failed to find USB HID device" << endl;
        exit(1);
	}

	if(!openHIDdevice(hidDev))
	{
        cout << "Error: failed to find USB HID device" << endl;
        exit(1);
	}

	if(hidDev->ProductID == 0x5021)
	{
        cout << "Warning: The product ID is 0x5021!  This may mean your internal EEPROM is corrupt." << endl;
        cout << "We will attempt to reset it." << endl;

		// For some reason, if you modify the internal EEPROM to change the serial number, the i1d3 returns back with the product code 0x5021
		//
		// Reading the internal EEPROM seems to reset this issue, but you MUST unplug and plug back in the USB connection
		// I think this resets the device driver ?

		int id = i1d3UnLock(hidDev);
		if(i1d3EnWrite(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			cout << "Error: Failed to enable i1d3 write mode" << endl;
			exit(1);
		}
		unsigned char fBuf[256];
		memset(fBuf, 0x00, 256);
		i1d3ReadInternalEeprom(hidDev, fBuf);

		if(fileName) delete[] fileName;
        cout << "Please disconnect then reconnect the USB before re-running this program" << endl;
		exit(1);
	}

	if(verNum)
	{
		char rBuf[64];
		memset(rBuf, 0x00, 64);
		i1d3GetInfo(hidDev, rBuf);
        cout << rBuf << endl;

		int id = i1d3UnLock(hidDev);

		switch(id)
		{
			case 0:
			{
				cout << "I1D3 Retail" << endl;
			}
			break;

			case 1:
			{
				cout << "I1D3 ColorMunkie" << endl;
			}
			break;

			case 2:
			{
				cout << "I1D3 OEM" << endl;
			}
			break;

			case 3:
			{
				cout << "I1D3 NEC" << endl;
			}
			break;

			case 4:
			{
				cout << "I1D3 Quato" << endl;
			}
			break;

			case 5:
			{
				cout << "I1D3 HP Dreamcolor" << endl;
			}
			break;

			case 6:
			{
				cout << "I1D3 Wacom" << endl;
			}
			break;

			case 7:
			{
				cout << "I1D3 SpectraCal C6" << endl;
			}
			break;

			case 8:
			{
				cout << "I1D3 Tpa3" << endl;
			}
			break;


			default:
			{
				cout << "Unknown signiture" << endl;
			}
		}
	}
	else if(rSerNum)
	{
		if(i1d3UnLock(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			cout << "Error: Failed to unlock the i1d3" << endl;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[256];
		memset(eBuf, 0x00, 256);
		i1d3ReadInternalEeprom(hidDev, eBuf);

		char serNum[21];
		memset(serNum, 0x00, 21);

		memcpy(serNum, &eBuf[16], 20);

		cout << serNum << endl;

		delete[] eBuf;
	}
	else if(wSerNum)
	{
		if(i1d3UnLock(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			cout << "Error: Failed to unlock the i1d3" << endl;
			exit(1);
		}

		if(i1d3EnWrite(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			cout << "Error: Failed to enable i1d3 write mode" << endl;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[256];
		memset(eBuf, 0x00, 256);
		i1d3ReadInternalEeprom(hidDev, eBuf);

		char serNum[21];
		memset(serNum, 0x00, 21);
		memcpy(serNum, fileName, 20);

		memcpy(&eBuf[16], serNum, 20);

		i1d3WriteInternalEeprom(hidDev, eBuf);

		cout << "Serial number " << fileName << " successfully written to the internal EEPROM" << endl;
		cout << "Now unplug and plugin the USB connection" << endl;

		delete[] eBuf;
	}
	else if(rIeeprom)
	{
		if(i1d3UnLock(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			cout << "Error: Failed to unlock the i1d3" << endl;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[256];
		memset(eBuf, 0x00, 256);
		if(!readInternalEepromStable(hidDev, eBuf))
		{
			cout << "Error: Internal EEPROM triple-read mismatch, aborting file write" << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		if(!writeFileBytes(fileName, eBuf, 256, forceOverWrite))
		{
			cout << "Error: Failed to write file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		if(!verifyFileMatches(fileName, eBuf, 256))
		{
			cout << "Error: File verification failed for " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		cout << "Internal EEPROM memory written and verified in file " << fileName << endl;

		delete[] eBuf;
	}
	else if(wIeeprom)
	{
		if(!validateFileSize(fileName, 256) && !forceOverWrite)
		{
			cout << "Error: Internal EEPROM input file must be exactly 256 bytes (use -f to force)" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[256];
		memset(eBuf, 0x00, 256);

		if(!readFileBytes(fileName, eBuf, 256))
		{
			cout << "Error: Failed to read file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		if(i1d3UnLock(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			delete[] eBuf;
			cout << "Error: Failed to unlock the i1d3" << endl;
			exit(1);
		}

		if(i1d3EnWrite(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			delete[] eBuf;
			cout << "Error: Failed to enable i1d3 write mode" << endl;
			exit(1);
		}

		i1d3WriteInternalEeprom(hidDev, eBuf);

		cout << "File " << fileName << " successfully written to the internal EEPROM" << endl;
		cout << "Now unplug and plugin the USB connection" << endl;

		delete[] eBuf;
	}
	else if(rEeeprom)
	{
		if(i1d3UnLock(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			cout << "Error: Failed to unlock the i1d3" << endl;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[8192];
		memset(eBuf, 0x00, 8192);
		if(!readExternalEepromStable(hidDev, eBuf))
		{
			cout << "Error: External EEPROM triple-read mismatch, aborting file write" << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		if(!writeFileBytes(fileName, eBuf, 8192, forceOverWrite))
		{
			cout << "Error: Failed to write file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		if(!verifyFileMatches(fileName, eBuf, 8192))
		{
			cout << "Error: File verification failed for " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		cout << "External EEPROM memory written and verified in file " << fileName << endl;

		delete[] eBuf;
	}
	else if(wEeeprom)
	{
		if(!validateFileSize(fileName, 8192) && !forceOverWrite)
		{
			cout << "Error: External EEPROM input file must be exactly 8192 bytes (use -f to force)" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[8192];
		memset(eBuf, 0x00, 8192);

		if(!readFileBytes(fileName, eBuf, 8192))
		{
			cout << "Error: Failed to read file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		if(i1d3UnLock(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			delete[] eBuf;
			cout << "Error: Failed to unlock the i1d3" << endl;
			exit(1);
		}

		if(i1d3EnWrite(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			delete[] eBuf;
			cout << "Error: Failed to enable i1d3 write mode" << endl;
			exit(1);
		}

		i1d3WriteExternalEeprom(hidDev, eBuf);

		cout << "File " << fileName << " successfully written to the external EEPROM" << endl;
		cout << "Now unplug and plugin the USB connection" << endl;

		delete[] eBuf;
	}
	else if(rSig)
	{
		unsigned char* eBuf = new unsigned char[8192];
		memset(eBuf, 0x00, 8192);
		if(!readExternalEepromStable(hidDev, eBuf))
		{
			cout << "Error: External EEPROM triple-read mismatch, aborting file write" << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		unsigned char* buf = new unsigned char[0x48];
		memset(buf, 0x00, 0x48);

		memcpy(buf, &eBuf[0x1638], 0x48);
		delete[] eBuf;

		if(!writeFileBytes(fileName, buf, 0x48, forceOverWrite))
		{
			cout << "Error: Failed to write file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] buf;
			exit(1);
		}

		if(!verifyFileMatches(fileName, buf, 0x48))
		{
			cout << "Error: File verification failed for " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] buf;
			exit(1);
		}

		cout << "External EEPROM signature written and verified in file " << fileName << endl;

		delete[] buf;
	}
	else if(wSig)
	{
		if(!validateFileSize(fileName, 0x48) && !forceOverWrite)
		{
			cout << "Error: Signature input file must be exactly 72 bytes (use -f to force)" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* buf = new unsigned char[0x48];
		memset(buf, 0x00, 0x48);

		if(!readFileBytes(fileName, buf, 0x48))
		{
			cout << "Error: Failed to read file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] buf;
			exit(1);
		}

		if(isBlockedRetailSignature(buf, 0x48) && !forceOverWrite)
		{
			cout << "Error: Refusing to write known invalid placeholder signature file." << endl;
			cout << "       This can soft-brick the probe: i1d3util/retail_I1D3signature.bin (use -f to override)" << endl;
			if(fileName) delete[] fileName;
			delete[] buf;
			exit(1);
		}

		if(i1d3UnLock(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			delete[] buf;
			cout << "Error: Failed to unlock the i1d3" << endl;
			exit(1);
		}

		if(i1d3EnWrite(hidDev) < 0)
		{
			if(fileName) delete[] fileName;
			delete[] buf;
			cout << "Error: Failed to enable i1d3 write mode" << endl;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[8192];
		memset(eBuf, 0x00, 8192);
		i1d3ReadExternalEeprom(hidDev, eBuf);

		unsigned int fsum(0);
		fsum =  eBuf[2] | (eBuf[3] << 8);
		unsigned int csum = calcCsum(eBuf);

		if(csum != fsum)
		{
			if(fileName) delete[] fileName;

			delete[] buf;
			delete[] eBuf;

			cout << "Error: Checksum of i1d3 external EEPROM failed.  This may mean it is not Rev2 hardware" << endl;
			exit(1);
		}

		memcpy(&eBuf[0x1638], buf, 0x48);

		csum = calcCsum(eBuf);
		eBuf[2] = (unsigned char)(csum >> 0) & 0xff;
		eBuf[3] = (unsigned char)(csum >> 8) & 0xff;

		
		i1d3WriteExternalEeprom(hidDev, eBuf);

		cout << "File " << fileName << " signature successfully written to the external EEPROM" << endl;
		cout << "Now unplug and plugin the USB connection" << endl;

		delete[] buf;
		delete[] eBuf;
	}
	else if(rAll)
	{
		if(i1d3UnLock(hidDev) < 0)
		{
			cout << "Error: Failed to unlock the i1d3" << endl;
			exit(1);
		}

		unsigned char* iBuf = new unsigned char[256];
		unsigned char* eBuf = new unsigned char[8192];
		unsigned char* sBuf = new unsigned char[0x48];
		if(!iBuf || !eBuf || !sBuf)
		{
			if(iBuf) delete[] iBuf;
			if(eBuf) delete[] eBuf;
			if(sBuf) delete[] sBuf;
			cout << "Error: Failed to allocate memory for -a dump" << endl;
			exit(1);
		}
		memset(iBuf, 0x00, 256);
		memset(eBuf, 0x00, 8192);
		memset(sBuf, 0x00, 0x48);

		if(!readInternalEepromStable(hidDev, iBuf))
		{
			cout << "Error: Internal EEPROM triple-read mismatch, aborting -a dump" << endl;
			delete[] iBuf;
			delete[] eBuf;
			delete[] sBuf;
			exit(1);
		}
		if(!readExternalEepromStable(hidDev, eBuf))
		{
			cout << "Error: External EEPROM triple-read mismatch, aborting -a dump" << endl;
			delete[] iBuf;
			delete[] eBuf;
			delete[] sBuf;
			exit(1);
		}

		memcpy(sBuf, &eBuf[0x1638], 0x48);

		char serialRaw[21];
		memset(serialRaw, 0x00, 21);
		memcpy(serialRaw, &iBuf[16], 20);

		char serialSafe[41];
		memset(serialSafe, 0x00, 41);
		int out(0);
		for(int i(0); i < 20 && serialRaw[i] != 0; ++i)
		{
			unsigned char ch = (unsigned char)serialRaw[i];
			if(isalnum(ch) || ch == '-' || ch == '_' || ch == '.')
			{
				serialSafe[out++] = (char)ch;
			}
			else if(ch == ' ')
			{
				serialSafe[out++] = '_';
			}
			else
			{
				serialSafe[out++] = '_';
			}
		}
		if(out == 0) strcpy(serialSafe, "unknown-serial");

		char internalFile[128];
		char externalFile[128];
		char signatureFile[128];
		snprintf(internalFile, sizeof(internalFile), "%s-internal.bin", serialSafe);
		snprintf(externalFile, sizeof(externalFile), "%s-external.bin", serialSafe);
		snprintf(signatureFile, sizeof(signatureFile), "%s-signature.bin", serialSafe);

		if(!writeFileBytes(internalFile, iBuf, 256, forceOverWrite) || !verifyFileMatches(internalFile, iBuf, 256))
		{
			cout << "Error: Failed to write/verify file " << internalFile << endl;
			delete[] iBuf;
			delete[] eBuf;
			delete[] sBuf;
			exit(1);
		}
		if(!writeFileBytes(externalFile, eBuf, 8192, forceOverWrite) || !verifyFileMatches(externalFile, eBuf, 8192))
		{
			cout << "Error: Failed to write/verify file " << externalFile << endl;
			delete[] iBuf;
			delete[] eBuf;
			delete[] sBuf;
			exit(1);
		}
		if(!writeFileBytes(signatureFile, sBuf, 0x48, forceOverWrite) || !verifyFileMatches(signatureFile, sBuf, 0x48))
		{
			cout << "Error: Failed to write/verify file " << signatureFile << endl;
			delete[] iBuf;
			delete[] eBuf;
			delete[] sBuf;
			exit(1);
		}

		cout << "Internal EEPROM saved and verified: " << internalFile << endl;
		cout << "External EEPROM saved and verified: " << externalFile << endl;
		cout << "Signature saved and verified: " << signatureFile << endl;

		delete[] iBuf;
		delete[] eBuf;
		delete[] sBuf;
	}

	if(fileName) delete[] fileName;

	closeHIDdevice(hidDev);
	hid_exit();


	return 0;
}
