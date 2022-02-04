/*
KakaoTalk.exe+F33DBE - E8 DD902000           - call KakaoTalk.exe+113CEA0 // get type

KakaoTalk.exe+F33E89 - E8 B2912000           - call KakaoTalk.exe+113D040

KakaoTalk.exe+E9C29B - E8 3046FCFF           - call KakaoTalk.exe+E60FD0  // encrypt()

KakaoTalk.exe+E606B0 - 53                    - push ebx   // decrypt

*/


  

var base = Process.findModuleByName("kakaotalk.exe");
var base_addr = ptr(base.base)



function get_addrof_dec(){
    var pattern="53 8b dc 83";
    var enc=get_addrof_enc()
    var result_get_dec_pattern = Memory.scanSync(base_addr.add(get_addrof_enc()).sub(0x300), 0x300, pattern)[0]
    var offset=result_get_dec_pattern.address-base_addr
    console.log("dec offset : ",offset)
    return offset
}

function get_addrof_dec(){
    var get_dec_pattern = "53 8B DC 83 EC 08 83 E4 F8 83 C4 04 55 8B 6B 04 89 6C 24 04 8B EC 6A FF 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 53 83 Ec 44 a1 ?? ?? ?? ?? 33 c5 89 45 EC 56 57 50 8D 45 f4 64 a3 00 00 00 00"
    var result_get_dec_pattern = Memory.scanSync(base.base, base.size, get_dec_pattern)[-1]
    console.log(result_get_dec_pattern.address)
    var offset=result_get_dec_pattern.address-base_addr
    console.log("dec offset : ",offset)
    return offset

}


function get_addrof_enc(){

    var get_type_pattern = "e8 ?? ?? ?? ?? 8d 45 ec c6 45 fc 01 50 8d 8d 1c ff ff ff e8"

    var result_get_type_pattern = Memory.scanSync(base.base, base.size, get_type_pattern)[0]
    var temp = result_get_type_pattern.address;
    var diff = Memory.readInt(temp.add(1))
    
    var offset=temp.add(diff).add(5)-base_addr;
    console.log("enc offset :",offset)
    return offset
}

function get_addrof_get_type(){


    var get_type_pattern = "ff 76 14 e8 ?? ?? ?? ?? 83 c4 08 6a 00 6a 00"

    var result_get_type_pattern = Memory.scanSync(base.base, base.size, get_type_pattern)[0]

    var temp = result_get_type_pattern.address.add(3);
    var diff = Memory.readInt(temp.add(1))
    var offset=temp.add(diff).add(5)-base_addr;
    console.log("get type offset :",offset)
    return offset

}


function get_addrof_msg(){
    var pattern="55 8b ec 56 8b 75 08 57 85 f6 74 4d 8b 06 8b 40 0c 85 c0 74 0a 50 ff ?? ?? ?? ?? ?? 83 c4 04";
    var result_get_dec_pattern = Memory.scanSync(base.base, base.size, pattern)[0]
    var offset=result_get_dec_pattern.address-base_addr
    console.log("get_msg offset : ",offset)
    return offset
}


var addr_get_type = base_addr.add(get_addrof_get_type());
var addr_get_msg  = base_addr.add(get_addrof_msg());
var addr_decrypt = base_addr.add(0xe60db0);

console.log("addr_get_type:",ptr(addr_get_type))
console.log("addr_get_msg:",ptr(addr_get_msg))
console.log("addr_get_type:",ptr(addr_decrypt))



var decrypt = new NativeFunction(addr_decrypt, 'pointer', ['pointer','pointer'],'fastcall')
// var decrypt2 = new NativeFunction(addr_decrypt, 'pointer', ['pointer','pointer'])

var flag = false;

var src = Memory.alloc(0x1024+8); 
var dst = Memory.alloc(0x1024);
var addr_src = Memory.alloc(8);
var addr_dst = Memory.alloc(8);

Memory.writePointer(src.add(4),ptr(0x4a))

Memory.writePointer(addr_src,src.add(8));
Memory.writePointer(src,ptr(0x226))
Memory.writePointer(addr_dst,dst);

console.log(src,addr_src)
console.log(Memory.readPointer(src),Memory.readPointer(addr_src))




Interceptor.attach(addr_get_type, {
    onLeave: function(ret){
        if(ret == 0x4001){
            ret.replace(1);
            flag = true;
        }
    //    console.log('return val :',ret)
    }
})

function getByteLengthOfUtf8String(s) {
	if(s != undefined && s != "") {
        var i;
        var b;
        var c;
		for(b=i=0;c=s.charCodeAt(i++);b+=c>>11?3:c>>7?2:1);
		return b;
	} else {
		return 0;
	}
}

Interceptor.attach(addr_get_msg, {
    onLeave: function(ret){
        if(flag){
            console.log("----------------------")
            flag = false;
            
            
            Memory.writePointer(addr_src,src.add(8));
            var strlength=getByteLengthOfUtf8String(Memory.readUtf8String(ret))
            Memory.writePointer(src,ptr(strlength))
            Memory.writeUtf8String(src.add(8),Memory.readUtf8String(ret))




            console.log(src,addr_src)
            console.log(Memory.readPointer(src),Memory.readPointer(addr_src))
            
            console.log("ret ",ret)
            console.log("ciper Text:",Memory.readUtf8String(ret))
            console.log(Memory.readByteArray(src,0x30))
            console.log(Memory.readByteArray(Memory.readPointer(addr_src).sub(8),0x60))




            
        
                console.log("fast call")
                decrypt(addr_dst,addr_src)
            
            ret.replace(Memory.readPointer(addr_dst))
    
        }
    }
})
