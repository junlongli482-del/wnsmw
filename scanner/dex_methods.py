"""Bounded DEX metadata/code-item reader for retained research artifacts."""
import struct

class Dex:
    def __init__(self,data):
        self.data=data
        if data[:4]!=b'dex\n' or self.u32(32)!=len(data):raise ValueError('DEX header/length mismatch')
        self.strings=[]
        for i in range(self.u32(56)):
            off=self.u32(self.u32(60)+i*4);_,pos=self.uleb(off)
            self.strings.append(data[pos:data.index(0,pos)].decode('utf-8','replace'))
        self.types=[self.strings[self.u32(self.u32(68)+i*4)] for i in range(self.u32(64))]
        self.protos=[]
        for i in range(self.u32(72)):
            _,ret,params=struct.unpack_from('<III',data,self.u32(76)+12*i)
            args=[self.types[struct.unpack_from('<H',data,params+4+2*j)[0]] for j in range(self.u32(params))] if params else []
            self.protos.append('('+''.join(args)+')'+self.types[ret])
        self.methods=[]
        for i in range(self.u32(88)):
            cls,proto,name=struct.unpack_from('<HHI',data,self.u32(92)+i*8)
            self.methods.append({'index':i,'class':self.types[cls],'name':self.strings[name],'descriptor':self.protos[proto]})
    def u32(self,off):return struct.unpack_from('<I',self.data,off)[0]
    def uleb(self,pos):
        value=0
        for shift in range(0,35,7):
            b=self.data[pos];pos+=1;value|=(b&127)<<shift
            if b<128:return value,pos
        raise ValueError('Invalid ULEB128')
    def defined_methods(self):
        for i in range(self.u32(96)):
            cls=self.u32(self.u32(100)+i*32);pos=self.u32(self.u32(100)+i*32+24)
            if not pos:continue
            counts=[]
            for _ in range(4):value,pos=self.uleb(pos);counts.append(value)
            for _ in range(counts[0]+counts[1]):
                _,pos=self.uleb(pos);_,pos=self.uleb(pos)
            for count in counts[2:]:
                index=0
                for _ in range(count):
                    diff,pos=self.uleb(pos);index+=diff;flags,pos=self.uleb(pos);code,pos=self.uleb(pos)
                    method=dict(self.methods[index],flags=flags,code_offset=code)
                    if method['class']!=self.types[cls]:raise ValueError('Class/method mismatch')
                    if code:
                        if code%4 or code+16>len(self.data):raise ValueError('Invalid code item offset')
                        units=self.u32(code+12);end=code+16+units*2
                        if end>len(self.data):raise ValueError('Code item out of bounds')
                        method['code_units']=units;method['insns_hex']=self.data[code+16:end].hex()
                    yield method
