
/* 
 * i1D3util.cpp
 *
 * Utility program for X-Rite i1d3 probes
 *
 * Date:   1/1/2020
 *
 * This material is licenced under the GNU GENERAL PUBLIC LICENSE Version 2 or later :-
 * see the License.txt file for licencing details.
 * 
 * 
 */


// Notes:
// 
// This work is shared AS IS.  You use it at your own risk.  It is possible, though unlikely that you could damage your probe if used.
//
// This work was inspired in part by the driver code from Argyll color management system
// full credit is given to Argyll’s author for any code similarities.
// https://www.argyllcms.com/
//
// Additional information was obtained by the use of the protocol analysis tool Wireshark
// https://www.wireshark.org/
// 
// Further information was obtained by extracting the firmware from i1d3 using PICKIT2 tools from Microchip and analysing it with Ghidra
// https://ghidra-sre.org/
//
// As a note, no Windows dlls were analysed in order to create i1d3util.  It was just not required!
//
//
//
//
//
// The i1d3 has both internal and external eeproms.  The internal eeprom contains the serial number, the external eeprom contains the unique
// device sensor calibration data and the “signature” that determines which flavour of i1d3 it is locked to (oem, retail, colormunki,C6 etc.)
// 
// The command i1d3util -? will give a help screen
//
// The i1d3util tool has a number of command line options, both in lowercase and uppercase.  Lowercase are read commands, uppercase are write commands.  
// The i1d3util tool can read the data out of the id3 and write it to disk, it can also take data on disk and write it back into the i1d3.  
// By doing this, you can backup and restore your probe.
//
// The i1d3util tool can access both internal and external eeprom data.  It can also specifically access/change the serial number and signature data.
//
// For example, if you have a retail probe and the signature data from an oem probe, you can load the oem signature into the retail probe.  
// The probe will now operate as if it were a factory oem probe.
//
// The –f option enables you to overwrite (without warning!!) a file on disk.
// The –w option enables ACTUAL writing to the i1d3 eeproms!
// The –v reads the firmware revision from the i1d3 hardware
// 
// Example command to load a oem probe signiture file into ANY i1d3 probe:
// 
// i1d3util -w -S oem1D3signature.bin
//
//
// It is STRONGLY RECOMMENDED that you save you probes current internal eeprom data, external eeprom data, 
// signature data and serial number before you start changing anything
//
// Be VERY careful to write the correct data file to the correct section of the probe!!
//
// It is possible to corrupt the internal eeprom.  If this happens, the i1d3 reports back a different USB Vendor ID.  
// The i1d3util will try and detect this and correct the problem.
//
// Between each WRITE to the i1d3, it is important that you unplug and plug back in the probe to reset the Windows device driver.
//
// Once a write operation has been performed, the i1d3 sometimes starts flashing its white LEDS.  This is normal, and is part of it visual feedback system.  
// Most application will either turn this off or allow you to turn it off/on
//
// Have fun!


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include <setupapi.h>

#include <math.h>
#include <iostream>
#include <fstream>


using namespace std;

int optind(1), optopt;
char* optarg;

#define BADCH   (int)'?'
#define BADARG  (int)':'
#define EMSG    ""

int getopt(int nargc, char * const nargv[], const char *ostr)
{
	static char *place = EMSG;              /* option letter processing */
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

/* Declartions to enable HID access without using the DDK */
#define DIDD_BUFSIZE sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA) + (sizeof(TCHAR)*MAX_PATH)

class hidIdevice
{
	public:
					hidIdevice():dpath(0), fh(0) {};
				   ~hidIdevice(){ if(dpath) delete[] dpath;};

	char*			dpath;
	HANDLE			fh;
	OVERLAPPED		ols;
	unsigned int	ProductID;
};


typedef struct _HIDD_ATTRIBUTES
{
	ULONG	Size;
	USHORT	VendorID;
	USHORT	ProductID;
	USHORT	VersionNumber;
} HIDD_ATTRIBUTES, *PHIDD_ATTRIBUTES;

typedef void (__stdcall *FP_HidD_GetHidGuid)   (LPGUID HidGuid);
typedef BOOL (__stdcall *FP_HidD_GetAttributes)(HANDLE , PHIDD_ATTRIBUTES Attributes);
FP_HidD_GetHidGuid    HidD_GetHidGuid;
FP_HidD_GetAttributes HidD_GetAttributes;

HINSTANCE loadDLLfuncs()
{
	static HINSTANCE lib(0);

	if(!lib)
	{
		lib = LoadLibrary("HID");
		if(lib)
		{
			HidD_GetHidGuid    = (FP_HidD_GetHidGuid)    GetProcAddress(lib, "HidD_GetHidGuid");
			HidD_GetAttributes = (FP_HidD_GetAttributes) GetProcAddress(lib, "HidD_GetAttributes");
		}

		if((HidD_GetHidGuid == 0) || (HidD_GetAttributes == 0)) lib = 0;
	}

	return lib;
}


hidIdevice* findHIDdevice()
{
	// Get the GUID for HIDClass devices
	GUID HidGuid;
	HidD_GetHidGuid(&HidGuid);

	// Get the device information for all devices of the HID class
	HDEVINFO hdinfo;
	hdinfo = SetupDiGetClassDevs(&HidGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE); 
	if(hdinfo == INVALID_HANDLE_VALUE) return 0;

	/* Get each devices interface data in turn */
	SP_DEVICE_INTERFACE_DATA diData;
	diData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	PSP_DEVICE_INTERFACE_DETAIL_DATA pdiDataDetail;
	char* diddBuf[DIDD_BUFSIZE];
	pdiDataDetail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)diddBuf;  
	pdiDataDetail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

	SP_DEVINFO_DATA dinfoData;
	dinfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	hidIdevice* hidDev(0);

	for(unsigned int c(0); ; ++c)
	{
		if(SetupDiEnumDeviceInterfaces(hdinfo, NULL, &HidGuid, c, &diData) == 0)
		{
			if (GetLastError() == ERROR_NO_MORE_ITEMS) break;

			return 0;
		}

		if(SetupDiGetDeviceInterfaceDetail(hdinfo, &diData, pdiDataDetail, DIDD_BUFSIZE, NULL, &dinfoData) == 0)
		{
			return 0;
		}

		// Extract the vid and pid from the device path
		unsigned int VendorID(0);
		unsigned int ProductID(0);
	
		char *cPtr;
		char cBuf[20];

		if((cPtr = strchr(pdiDataDetail->DevicePath, 'v')) == NULL) continue;
		if(strlen(cPtr) < 8) continue;
		if(cPtr[1] != 'i' || cPtr[2] != 'd' || cPtr[3] != '_') continue;
		memcpy(cBuf, cPtr + 4, 4);
		cBuf[4] = 0;
		if(sscanf(cBuf, "%x", &VendorID) != 1) continue;

		if((cPtr = strchr(pdiDataDetail->DevicePath, 'p')) == NULL) continue;
		if(strlen(cPtr) < 8) break;
		if(cPtr[1] != 'i' || cPtr[2] != 'd' || cPtr[3] != '_') continue;
		memcpy(cBuf, cPtr + 4, 4);
		cBuf[4] = 0;
		if(sscanf(cBuf, "%x", &ProductID) != 1) break;

		//Is it an X-Rite i1DisplayPro, ColorMunki Display (HID)
		if((VendorID == 0x0765) && ((ProductID == 0x5020) || (ProductID == 0x5021)))
		{
			hidDev = new hidIdevice;
			if(!hidDev) return 0;
			hidDev->dpath = new char[strlen(pdiDataDetail->DevicePath) + 2];
			if(!hidDev->dpath) return 0;
			memset(hidDev->dpath, 0x00, strlen(pdiDataDetail->DevicePath) + 2);

			/* Windows 10 seems to return paths without the leading '\\' */
			if(pdiDataDetail->DevicePath[0] == '\\' &&	pdiDataDetail->DevicePath[1] != '\\') strcpy(hidDev->dpath, "\\");
			strcpy(hidDev->dpath, pdiDataDetail->DevicePath);

			hidDev->ProductID = ProductID;

			break;
		}
	}

	//cleanup hdifo
	if(SetupDiDestroyDeviceInfoList(hdinfo) == 0) return 0;

    return hidDev;
}


bool openHIDdevice(hidIdevice* dev)
{
	// Open the device
	dev->fh = CreateFile(dev->dpath, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

	if(dev != INVALID_HANDLE_VALUE)
	{
		memset(&dev->ols,0,sizeof(OVERLAPPED));
		dev->ols.hEvent = CreateEvent(NULL, 0, 0, NULL);
  		if(dev->ols.hEvent == NULL) return false;
		
		return true;
	}

	return false;
}


void closeHIDdevice(hidIdevice* dev)
{
	if(dev != NULL)
	{
		CloseHandle(dev->ols.hEvent);
		CloseHandle(dev->fh);
	}
}


int	readHIDdevice(hidIdevice* dev, unsigned char* rbuf,	int numToRead, double timeout)
{
	int numRead(0);

	unsigned char* lBuf;
	lBuf = new unsigned char[numToRead + 1];
	if(!lBuf) return -1;
	memset(lBuf, 0x00, numToRead + 1);

	if (ReadFile(dev->fh, lBuf, numToRead + 1, (LPDWORD)&numRead, &dev->ols) == 0)
	{
		if(GetLastError() != ERROR_IO_PENDING)
		{
			numRead = -1; 
		}
		else
		{
			int res;
			res = WaitForSingleObject(dev->ols.hEvent, (int)(timeout * 1000.0 + 0.5));
			if(res == WAIT_FAILED)
			{
				numRead = -1;
			}
			else if
			(res == WAIT_TIMEOUT)
			{
				CancelIo(dev->fh);
				numRead = -1;
			}
			else
			{
				numRead = dev->ols.InternalHigh;
			}
		}
	}

	if(numRead > 0)
	{
		numRead--;
		memcpy(rbuf, lBuf + 1, numRead);
	}

	delete[] lBuf;

	return numRead;
}


int writeHIDdevice(hidIdevice* dev,	unsigned char* wbuf, int numToWrite, double timeout = 1.0)
{
	int numWritten(0);

	unsigned char* lBuf;
	lBuf = new unsigned char[numToWrite + 1];
	if(!lBuf) return -1;
	memset(lBuf, 0x00, numToWrite + 1);
	memcpy(lBuf + 1, wbuf, numToWrite);

	if(WriteFile(dev->fh, lBuf, numToWrite + 1, (LPDWORD)&numWritten, &dev->ols) == 0)
	{ 
		if (GetLastError() != ERROR_IO_PENDING)
		{
			numWritten = -1; 
		}
		else
		{
			int res;
			res = WaitForSingleObject(dev->ols.hEvent, (int)(timeout * 1000.0 + 0.5));
			if (res == WAIT_FAILED)
			{
				numWritten = -1; 
			}
			else if (res == WAIT_TIMEOUT)
			{
				CancelIo(dev->fh);
				numWritten = -1; 
			}
			else
			{
				numWritten = dev->ols.InternalHigh;
			}
		}
	}

	if(numWritten > 0)
	{
		numWritten--;
	}

	delete[] lBuf;

	return numWritten;
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
		i1d3Command(dev, cmd, tBuf, fBuf);

		// Convert challenge to response
		i1d3CreateUnLockResponse(i1d3UnLockKeys[cc][0], i1d3UnLockKeys[cc][1], fBuf, tBuf);

		// Send the response
		cmd = 0x9a00;
		i1d3Command(dev, cmd, tBuf, fBuf);

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

	i1d3Command(dev, cmd, tBuf, fBuf);

	return -1;
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


//extern char *optarg;
//extern int optind, opterr, optopt;

int main(int argc, char **argv)
{
	cout << "i1d3util ver 1.0" << endl;


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

    int   opt(0);
    while(1)
    {
        opt = getopt(argc, argv, "fwvnNiIeEsS");
        
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
            cout << " -i              read the internal eeprom and write it to a file"		<< endl;
            cout << " -I              read a file and load it into the internal eeprom"		<< endl;
	        cout																			<< endl;
            cout << " -e              read the external eeprom and write it to a file"		<< endl;
            cout << " -E              read a file and load it into the external eeprom"		<< endl;
	        cout																			<< endl;
            cout << " -s              read external eeprom signature and write to a file"	<< endl;
            cout << " -S              read a signature file and update the external eeprom"	<< endl;
	        cout																			<< endl;
            cout << " -f              force file overwrite"									<< endl;
            cout << " -w              enable eeprom writing"								<< endl;
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
	
	if(wSerNum && !fileName)
	{
		cout << "Error: missing serial number" << endl;
		exit(1);
	}

    if(!fileName && !verNum && !rSerNum && !wSerNum && !rIeeprom && !wIeeprom && !rEeeprom && !wEeeprom && !rSig && !wSig)
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
        cout << "Warning: The product ID is 0x5021!  This may mean you internal eeprom is corrupt." << endl;
        cout << "We will attempt to reset it." << endl;

		// For some reason, if you modify the internal eeprom to change the serial number, the i1d3 returns back with the product code 0x5021
		//
		// Reading the internal eeprom seems to reset this issue, but you MUST unplug and plug back in the USB connection
		// I think this resets the device driver ?

		int id = i1d3UnLock(hidDev);
		i1d3EnWrite(hidDev);
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

		i1d3EnWrite(hidDev);

		unsigned char* eBuf = new unsigned char[256];
		memset(eBuf, 0x00, 256);
		i1d3ReadInternalEeprom(hidDev, eBuf);

		char serNum[21];
		memset(serNum, 0x00, 21);
		memcpy(serNum, fileName, 20);

		memcpy(&eBuf[16], serNum, 20);

		if(enableEEPROMwrite) i1d3WriteInternalEeprom(hidDev, eBuf);
		else cout << "EEPROM write not enabled, use -w" << endl;

		cout << "Serial number " << fileName << " successfully written to the internal eeprom" << endl;
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

		HANDLE hd;
		if(forceOverWrite)
		{
			hd = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		}
		else
		{
			hd = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
		}

		if(hd == INVALID_HANDLE_VALUE)
		{
			cout << "Error: Failed to open file " << fileName << " for writing" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		if(SetFilePointer(hd, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			cout << "Error: Failed to open file " << fileName << " for writing" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[256];
		memset(eBuf, 0x00, 256);
		i1d3ReadInternalEeprom(hidDev, eBuf);

		DWORD noWritten(0);
		if(!WriteFile(hd, eBuf, 256, &noWritten, NULL)) return -1;
		if (noWritten != 256)
		{
			cout << "Error: Failed to write file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		cout << "Internal eeprom memory written to file " << fileName << endl;

		if(!CloseHandle(hd))
		{
			cout << "Error: Failed to close file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		delete[] eBuf;
	}
	else if(wIeeprom)
	{
		HANDLE hd = CreateFile(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if(hd == INVALID_HANDLE_VALUE)
		{
			cout << "Error: Failed to open file " << fileName << " for reading" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		if(SetFilePointer(hd, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			cout << "Error: Failed to open file " << fileName << " for reading" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[256];
		memset(eBuf, 0x00, 256);

		DWORD noRead(0);
		if(!ReadFile(hd, eBuf, 256, &noRead, NULL)) return -1;
		if (noRead != 256)
		{
			cout << "Error: Failed to read file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		if(!CloseHandle(hd))
		{
			cout << "Error: Failed to close file " << fileName << endl;
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

		i1d3EnWrite(hidDev);

		if(enableEEPROMwrite) i1d3WriteInternalEeprom(hidDev, eBuf);
		else cout << "EEPROM write not enabled, use -w" << endl;

		cout << "File " << fileName << " successfully written to the internal eeprom" << endl;
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

		HANDLE hd;
		if(forceOverWrite)
		{
			hd = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		}
		else
		{
			hd = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
		}

		if(hd == INVALID_HANDLE_VALUE)
		{
			cout << "Error: Failed to open file " << fileName << " for writing" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		if(SetFilePointer(hd, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			cout << "Error: Failed to open file " << fileName << " for writing" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[8192];
		memset(eBuf, 0x00, 8192);
		i1d3ReadExternalEeprom(hidDev, eBuf);

		DWORD noWritten(0);
		if(!WriteFile(hd, eBuf, 8192, &noWritten, NULL)) return -1;
		if (noWritten != 8192)
		{
			cout << "Error: Failed to write file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		cout << "External eeprom memory written to file " << fileName << endl;

		if(!CloseHandle(hd))
		{
			cout << "Error: Failed to close file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		delete[] eBuf;
	}
	else if(wEeeprom)
	{
		HANDLE hd = CreateFile(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if(hd == INVALID_HANDLE_VALUE)
		{
			cout << "Error: Failed to open file " << fileName << " for reading" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		if(SetFilePointer(hd, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			cout << "Error: Failed to open file " << fileName << " for reading" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[8192];
		memset(eBuf, 0x00, 8192);

		DWORD noRead(0);
		if(!ReadFile(hd, eBuf, 8192, &noRead, NULL)) return -1;
		if (noRead != 8192)
		{
			cout << "Error: Failed to read file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		if(!CloseHandle(hd))
		{
			cout << "Error: Failed to close file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] eBuf;
			exit(1);
		}

		i1d3UnLock(hidDev);

		i1d3EnWrite(hidDev);

		if(enableEEPROMwrite) i1d3WriteExternalEeprom(hidDev, eBuf);
		else cout << "EEPROM write not enabled, use -w" << endl;

		cout << "File " << fileName << " successfully written to the external eeprom" << endl;
		cout << "Now unplug and plugin the USB connection" << endl;

		delete[] eBuf;
	}
	else if(rSig)
	{
		HANDLE hd;
		if(forceOverWrite)
		{
			hd = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		}
		else
		{
			hd = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
		}

		if(hd == INVALID_HANDLE_VALUE)
		{
			cout << "Error: Failed to open file " << fileName << " for writing" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		if(SetFilePointer(hd, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			cout << "Error: Failed to open file " << fileName << " for writing" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* eBuf = new unsigned char[8192];
		memset(eBuf, 0x00, 8192);
		i1d3ReadExternalEeprom(hidDev, eBuf);

		unsigned char* buf = new unsigned char[0x48];
		memset(buf, 0x00, 0x48);

		memcpy(buf, &eBuf[0x1638], 0x48);
		delete[] eBuf;

		DWORD noWritten(0);
		if(!WriteFile(hd, buf, 0x48, &noWritten, NULL)) return -1;
		if (noWritten != 0x48)
		{
			cout << "Error: Failed to write file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] buf;
			exit(1);
		}

		cout << "External eeprom memory written to file " << fileName << endl;

		if(!CloseHandle(hd))
		{
			cout << "Error: Failed to close file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] buf;
			exit(1);
		}

		delete[] buf;
	}
	else if(wSig)
	{
		HANDLE hd = CreateFile(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if(hd == INVALID_HANDLE_VALUE)
		{
			cout << "Error: Failed to open file " << fileName << " for reading" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		if(SetFilePointer(hd, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		{
			cout << "Error: Failed to open file " << fileName << " for reading" << endl;
			if(fileName) delete[] fileName;
			exit(1);
		}

		unsigned char* buf = new unsigned char[0x48];
		memset(buf, 0x00, 0x48);

		DWORD noRead(0);
		if(!ReadFile(hd, buf, 0x48, &noRead, NULL)) return -1;
		if (noRead != 0x48)
		{
			cout << "Error: Failed to read file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] buf;
			exit(1);
		}

		if(!CloseHandle(hd))
		{
			cout << "Error: Failed to close file " << fileName << endl;
			if(fileName) delete[] fileName;
			delete[] buf;
			exit(1);
		}

		i1d3UnLock(hidDev);

		i1d3EnWrite(hidDev);

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

			cout << "Error: Checksum of i1d3 external eeprom failed.  This may mean it is not Rev2 hardware" << endl;
			exit(1);
		}

		memcpy(&eBuf[0x1638], buf, 0x48);

		csum = calcCsum(eBuf);
		eBuf[2] = (unsigned char)(csum >> 0) & 0xff;
		eBuf[3] = (unsigned char)(csum >> 8) & 0xff;

		
		if(enableEEPROMwrite) i1d3WriteExternalEeprom(hidDev, eBuf);
		else cout << "EEPROM write not enabled, use -w" << endl;

		cout << "File " << fileName << " signature successfully written to the external eeprom" << endl;
		cout << "Now unplug and plugin the USB connection" << endl;

		delete[] buf;
		delete[] eBuf;
	}

	if(fileName) delete[] fileName;

	closeHIDdevice(hidDev);


	return 0;
}
