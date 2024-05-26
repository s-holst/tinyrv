import struct, sys, math
def zext(length, word): return word&((1<<length)-1)
def sext(length, word): return word|~((1<<length)-1) if word&(1<<(length-1)) else zext(length, word)

RM_RNE = 0  # nearest, ties to even
RM_RTZ = 1  # towards zero
RM_RDN = 2  # towards -inf
RM_RUP = 3  # towards +inf
RM_RMM = 4  # nearest, ties to max magnitude (away from zero)

FLAG_NX = 0x01  # inexact
FLAG_UF = 0x02  # underflow
FLAG_OF = 0x04  # overflow
FLAG_DZ = 0x08  # division by zero
FLAG_NV = 0x10  # invalid

def shift_right_and_round(s_s, s_sign, shift, rm=RM_RNE):
    if shift <= 0: return s_s<<(-shift), False, False
    round = s_s&(1 << (shift-1)) != 0
    sticky = s_s&((1 << (shift-1))-1) != 0
    s_s = s_s >> shift
    pre_length = s_s.bit_length()
    s_s += (rm==RM_RNE and (round and (sticky or s_s&1)) or
            rm==RM_RDN and ((round or sticky) and s_sign) or
            rm==RM_RUP and ((round or sticky) and not s_sign) or
            rm==RM_RMM and round)
    return s_s, round or sticky, s_s.bit_length() > pre_length

class f32:
    def __init__(self, float_or_raw, flags=0):
        self.raw = zext(32, float_or_raw) if isinstance(float_or_raw, int) else struct.unpack('I', struct.pack('f', float_or_raw))[0]
        self.float = struct.unpack('f', struct.pack('I', self.raw))[0]
        self.flags = flags
        self.is_zero = (self.raw&0x7fffffff) == 0
        self.is_neg = (self.raw&0x80000000) != 0
        self.is_inf = self.raw&0x7fffffff == 0x7f800000
        self.is_nan = self.raw&0x7fffffff > 0x7f800000
        self.is_qnan = self.raw&0x7fffffff >= 0x7fc00000
        self.is_snan = self.is_nan and not self.is_qnan
        self.e = ((self.raw&0x7f800000)>>23) - 127
        self.is_subnormal = (self.e==-127) and not self.is_zero
        self.is_normal = not (self.is_subnormal or self.is_inf or self.is_nan or self.is_zero)
        if self.is_subnormal: self.s = self.raw&0x007fffff; self.e -= 23-self.s.bit_length()
        elif self.is_zero: self.s = 0
        else: self.s = self.raw&0x007fffff | (0x800000 * (self.e!=128)) # + implicit 1. if not nan or inf
        self.flag_inexact = False
        self.flag_invalid = False
        self.flag_overflow = False
    @classmethod
    def min(cls, a, b):
        a, b = cls(a), cls(b)
        r = b if a.is_nan else a if b.is_nan else cls(a.raw|b.raw) if a.is_zero and b.is_zero else cls(min(a.float, b.float))
        r.flags = FLAG_NV*(a.is_snan or b.is_snan)
        return cls(float('nan'), r.flags) if r.is_nan else r
    @classmethod
    def max(cls, a, b):
        a, b = cls(a), cls(b)
        r = b if a.is_nan else a if b.is_nan else cls(a.raw&b.raw) if a.is_zero and b.is_zero else cls(max(a.float, b.float))
        r.flags = FLAG_NV*(a.is_snan or b.is_snan)
        return cls(float('nan'), r.flags) if r.is_nan else r
    def to_u32_and_flags(self, rm=0): v, f = self.to_int_and_flags_bounds(0       , (1<<32)-1, rm); return sext(32, v), f
    def to_u64_and_flags(self, rm=0): v, f = self.to_int_and_flags_bounds(0       , (1<<64)-1, rm); return sext(64, v), f
    def to_i32_and_flags(self, rm=0): v, f = self.to_int_and_flags_bounds(-(1<<31), (1<<31)-1, rm); return sext(32, v), f
    def to_i64_and_flags(self, rm=0): v, f = self.to_int_and_flags_bounds(-(1<<63), (1<<63)-1, rm); return sext(64, v), f
    def to_int_and_flags_bounds(self, lower, upper, rm=0):
        if self.is_nan: return upper, FLAG_NV
        if self.is_inf: return lower if self.is_neg else upper, FLAG_NV
        v = self.to_int(rm)
        if v > upper: return upper, FLAG_NV
        elif v < lower: return lower,  FLAG_NV
        return v, FLAG_NX*(v!=self.float)
    def to_int(self, rm=0):
        if rm==RM_RNE or rm==RM_RMM and int(self.float*2)!=self.float*2: return round(self.float)
        if rm==RM_RTZ: return int(self.float)
        if rm==RM_RDN: return math.floor(self.float)
        if rm==RM_RUP: return math.ceil(self.float)
        if rm==RM_RMM: return math.ceil(self.float) if self.float > 0 else int(self.float)  # RMM break tie away from zero
    @classmethod
    def normalized(cls, s_s, s_e, s_sign, rm=0):
        flag_inexact = False
        flag_overflow = False
        if s_s == 0: return cls(0x80000000 * s_sign)  # zeros
        if s_e <= -127:  # subnormal
            shift = 24-s_s.bit_length()
            s_s, flag_inexact, carry = shift_right_and_round(s_s, s_sign, -shift+(-s_e-127+1), rm)  # TODO: carry handling?
            #print(hex(s_s), flag_inexact, carry)
            s_e = -127 if s_s&0x800000 == 0 else -126  # carry to the top? not subnormal anymore
        else:
            shift = 24-s_s.bit_length()
            s_s, flag_inexact, carry = shift_right_and_round(s_s, s_sign, -shift, rm)
            if carry:
                s_e += 1
        if s_e > 127:
            if (rm==2 or rm==1) and not s_sign:  # RDN,RTZ cannot generate +inf
                v = cls(0x7f7fffff)
            elif (rm==3 or rm==1) and s_sign: # RUP,RTZ cannot generate -inf
                v = cls(0xff7fffff)
            else:
                v = cls(0x7f800000 | (0x80000000 * s_sign)) # inf
            v.flag_inexact = True
            v.flag_overflow = True
            return v
        v = cls((s_e+127) << 23 | (s_s&0x7fffff) | (0x80000000 * s_sign))
        v.flag_inexact = flag_inexact
        return v

    @classmethod
    def div(cls, a, b, rm=0):
        a, b = cls(a), cls(b)
        flags = FLAG_NV*(a.is_snan or b.is_snan)
        if a.is_nan or b.is_nan: return cls(0x7fc00000, flags)
        if b.is_zero:
            if a.is_zero: return cls(0x7fc00000, FLAG_NV)
            else:
                if not a.is_inf: flags |= FLAG_DZ
                return cls(float('-inf'), flags) if a.is_neg != b.is_neg else cls(float('inf'), flags)
        if a.is_inf:
            if b.is_inf: return cls(0x7fc00000, FLAG_NV)
            return cls(float('-inf'), flags) if a.is_neg != b.is_neg else cls(float('inf'), flags)
        if b.is_inf: return cls(-0.0, flags) if a.is_neg != b.is_neg else cls(0.0, flags)

        a_s = a.s << (128-a.s.bit_length())
        b_s = b.s << (64-b.s.bit_length())
        r_s = a_s // b_s
        r_e = a.e - b.e - 65 + r_s.bit_length()
        r = f32.normalized(r_s, r_e, a.is_neg != b.is_neg, rm)
        r.flags |= FLAG_NX*r.flag_inexact
        r.flags |= FLAG_UF*(r.flag_inexact and (r.is_zero or r.is_subnormal))
        r.flags |= FLAG_OF*r.flag_overflow
        return r

    @classmethod
    def mul(cls, a, b, rm=0):
        a, b = f32(a), f32(b)
        flags = FLAG_NV*(a.is_snan or b.is_snan)
        if a.is_nan or b.is_nan: return cls(0x7fc00000, flags)
        if a.is_inf or b.is_inf:
            if a.is_zero or b.is_zero: return cls(0x7fc00000, FLAG_NV)
            return cls(float('-inf'), flags) if a.is_neg != b.is_neg else cls(float('inf'), flags)
        if a.is_zero or b.is_zero: return cls(-0.0, flags) if a.is_neg != b.is_neg else cls(0.0, flags)
        r_s = a.s * b.s
        r_e = a.e + b.e + r_s.bit_length() - a.s.bit_length() - b.s.bit_length() + 1
        r = f32.normalized(r_s, r_e, a.is_neg != b.is_neg, rm)
        r.flags |= FLAG_NX*r.flag_inexact
        r.flags |= FLAG_UF*(r.flag_inexact and (r.is_zero or r.is_subnormal))
        r.flags |= FLAG_OF*r.flag_overflow
        return r

    @classmethod
    def add(cls, a, b, rm=0):
        a, b = f32(a), f32(b)
        flags = FLAG_NV*(a.is_snan or b.is_snan)
        if a.is_nan or b.is_nan: return cls(0x7fc00000, flags)
        if a.is_inf or b.is_inf:
            if a.is_inf and b.is_inf and a.is_neg != b.is_neg: return cls(0x7fc00000, FLAG_NV)
            else: return a if a.is_inf else b
        a_s = -a.s if a.is_neg else a.s
        b_s = -b.s if b.is_neg else b.s
        shift = a.e-b.e-a.s.bit_length()+b.s.bit_length()
        bl_base = 0
        if shift > 0:
            a_s = a_s << shift
            bl_base = b.s.bit_length()
            s_e = b.e
        else:
            b_s = b_s << -shift
            bl_base = a.s.bit_length()
            s_e = a.e
        s_s = a_s + b_s
        s_sign = s_s < 0
        s_s = -s_s if s_sign else s_s
        s_e = s_e - (bl_base-s_s.bit_length())
        if a.is_zero and b.is_zero and a.is_neg and b.is_neg: s_sign = True  # special case: -0 + -0 = -0
        else: s_sign = rm==RM_RDN if s_s==0 else s_sign # -0 when rounding down, else +0
        r = cls.normalized(s_s, s_e, s_sign, rm)
        r.flags |= FLAG_NX*r.flag_inexact
        r.flags |= FLAG_UF*(r.flag_inexact and (r.is_zero or r.is_subnormal))
        r.flags |= FLAG_OF*r.flag_overflow
        return r

    @classmethod
    def mad(cls, a, b, c, rm=0, negate_product=False):
        a, b, c = cls(a), cls(b), cls(c)
        flags = FLAG_NV*(a.is_snan or b.is_snan or c.is_snan)
        if a.is_nan or b.is_nan: return cls(0x7fc00000, flags)
        if a.is_inf or b.is_inf:
            if a.is_zero or b.is_zero: return cls(0x7fc00000, FLAG_NV)
            if a.is_nan or b.is_nan or c.is_nan: return cls(0x7fc00000, flags)
            s_sign = a.is_neg != b.is_neg
            s_sign = s_sign != negate_product
            if c.is_inf and c.is_neg != s_sign: return cls(0x7fc00000, FLAG_NV)
            return cls(float('-inf'), flags) if s_sign else cls(float('inf'), flags)
        if a.is_nan or b.is_nan or c.is_nan: return cls(0x7fc00000, flags)
        r_s = a.s * b.s
        r_e = a.e + b.e + r_s.bit_length() - a.s.bit_length() - b.s.bit_length() + 1
        r_sign = a.is_neg == b.is_neg if negate_product else a.is_neg != b.is_neg
        if c.is_inf: return c

        r_s = -r_s if r_sign else r_s
        c_s = -c.s if c.is_neg else c.s
        shift = r_e-c.e-r_s.bit_length()+c.s.bit_length()
        bl_base = 0
        if shift > 0:
            r_s = r_s << shift
            bl_base = c_s.bit_length()
            s_e = c.e
        else:
            c_s = c_s << -shift
            bl_base = r_s.bit_length()
            s_e = r_e
        s_s = r_s + c_s
        s_sign = s_s < 0
        s_s = -s_s if s_sign else s_s
        s_e = s_e - (bl_base-s_s.bit_length())
        if r_s == 0 and c.is_zero and r_sign == c.is_neg: s_sign = r_sign  # fixes special case of -0 + -0 = -0
        else: s_sign = rm==RM_RDN if s_s==0 else s_sign # -0 when rounding down, else +0
        r = f32.normalized(s_s, s_e, s_sign, rm)
        r.flags |= FLAG_NX*r.flag_inexact
        r.flags |= FLAG_UF*(r.flag_inexact and (r.is_zero or r.is_subnormal))
        r.flags |= FLAG_OF*r.flag_overflow
        return r

    @classmethod
    def sqrt(cls, a, rm=0):
        a = cls(a)
        flags = FLAG_NV*(a.is_snan)
        if a.is_nan: return cls(0x7fc00000, flags)
        if a.is_zero: return cls(0x80000000*a.is_neg, flags)
        if a.is_neg: return cls(0x7fc00000, FLAG_NV)
        if a.is_inf: return cls(0x7f800000)
        r_raw = struct.unpack('Q', struct.pack('d', a.float**0.5))[0]  # use 64-bit sqrt
        r_e = ((r_raw>>52)&0x7ff) - 1023
        r_s = r_raw&0xfffff_ffffffff | (0x100000_00000000 * (r_e!=-1023))
        r_sign = r_raw&0x80000000_00000000 != 0
        r = f32.normalized(r_s, r_e, r_sign, rm)
        r.flags |= FLAG_NX*r.flag_inexact
        r.flags |= FLAG_UF*(r.flag_inexact and (r.is_zero or r.is_subnormal))
        r.flags |= FLAG_OF*r.flag_overflow
        return r

    def __repr__(self) -> str:
        return (('n ' if self.is_neg else '  ') +
                ('i ' if self.is_inf else '  ') +
                ('qn' if self.is_qnan else '  ') +
                ('sn' if self.is_snan else '  ') + f's: {self.s:b} e: {self.e} float: {self.float} raw: {hex(self.raw)}')

if __name__ == "__main__":
    p = [float(a) if '.' in a or 'inf' in a.lower() or 'nan' in a.lower() else int(a, 16) for a in sys.argv[1:]]
    print(f32(p[0]))
    #print(f32(p[1]))
    #print(f32(p[2]))
    r = f32.sqrt(p[0], rm=0)
    print(r, bin(r.flags))
