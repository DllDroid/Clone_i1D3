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
