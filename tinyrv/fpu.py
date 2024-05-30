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

class flt:
    def __init__(self, f, raw, flags=0):
        self.float, self.raw, self.flags = f, raw, flags
        self.is_neg = (self.raw&self.SIGN_BIT) != 0
        self.is_zero = (self.raw&self.ABS_MASK) == 0
        self.is_inf = self.raw&self.ABS_MASK == self.EXP_MASK
        self.is_nan = self.raw&self.ABS_MASK > self.EXP_MASK
        self.is_qnan = self.raw&self.ABS_MASK >= self.QNAN
        self.is_snan = self.is_nan and not self.is_qnan
        self.e = ((self.raw&self.EXP_MASK)>>self.TLEN) - self.EXP_BIAS
        self.is_subnormal = (self.e==-self.EXP_BIAS) and not self.is_zero
        self.flags |= FLAG_UF*((flags&FLAG_NX!=0) and (self.is_zero or self.is_subnormal))  # set underflow flag automatically
        self.is_normal = not (self.is_subnormal or self.is_inf or self.is_nan or self.is_zero)
        self.s = self.raw&self.TSIG_MASK
        if self.is_subnormal: self.e -= self.TLEN-self.s.bit_length()  # reduce exp by number of leading zeros
        elif self.is_normal: self.s |= self.SIG_ONE  # + implicit 1. if not (nan or inf or zero or subnormal)

    @classmethod
    def normalized(cls, s_s, s_e, s_sign, rm=0):
        flag_inexact = False
        if s_s == 0: return cls(cls.SIGN_BIT*s_sign)  # zeros
        if s_e <= -cls.EXP_BIAS:  # subnormal
            shift = (cls.TLEN+1)-s_s.bit_length()
            s_s, flag_inexact, carry = shift_right_and_round(s_s, s_sign, -shift+(-s_e-cls.EXP_BIAS+1), rm)
            s_e = -cls.EXP_BIAS if s_s&cls.SIG_ONE == 0 else -cls.EXP_BIAS+1  # carry to the top? not subnormal anymore
        else:
            shift = (cls.TLEN+1)-s_s.bit_length()
            s_s, flag_inexact, carry = shift_right_and_round(s_s, s_sign, -shift, rm)
            if carry: s_e += 1
        if s_e > cls.EXP_BIAS:  # overflow
            if (rm==RM_RDN or rm==RM_RTZ) and not s_sign: return cls(cls.FMAX, FLAG_NX|FLAG_OF)  # RDN,RTZ cannot generate +inf
            elif (rm==RM_RUP or rm==RM_RTZ) and s_sign: return cls(cls.FMAX|cls.SIGN_BIT, FLAG_NX|FLAG_OF)  # RUP,RTZ cannot generate -inf
            else: return cls(cls.EXP_MASK | (cls.SIGN_BIT*s_sign), FLAG_NX|FLAG_OF) # +/-inf
        return cls((s_e+cls.EXP_BIAS) << cls.TLEN | (s_s&cls.TSIG_MASK) | (cls.SIGN_BIT * s_sign), FLAG_NX*flag_inexact)

    @classmethod
    def min(cls, a, b):
        a, b = cls(a), cls(b)
        r = b if a.is_nan else a if b.is_nan else cls(a.raw|b.raw) if a.is_zero and b.is_zero else cls(min(a.float, b.float))
        r.flags = FLAG_NV*(a.is_snan or b.is_snan)
        return cls(cls.QNAN, r.flags) if r.is_nan else r

    @classmethod
    def max(cls, a, b):
        a, b = cls(a), cls(b)
        r = b if a.is_nan else a if b.is_nan else cls(a.raw&b.raw) if a.is_zero and b.is_zero else cls(max(a.float, b.float))
        r.flags = FLAG_NV*(a.is_snan or b.is_snan)
        return cls(cls.QNAN, r.flags) if r.is_nan else r

    def to_u32_and_flags(self, rm=0): v, f = self.to_int_and_flags_bounds(0       , (1<<32)-1, rm); return sext(32, v), f
    def to_u64_and_flags(self, rm=0): v, f = self.to_int_and_flags_bounds(0       , (1<<64)-1, rm); return sext(64, v), f
    def to_i32_and_flags(self, rm=0): v, f = self.to_int_and_flags_bounds(-(1<<31), (1<<31)-1, rm); return sext(32, v), f
    def to_i64_and_flags(self, rm=0): v, f = self.to_int_and_flags_bounds(-(1<<63), (1<<63)-1, rm); return sext(64, v), f
    def to_int_and_flags_bounds(self, lower, upper, rm=0):
        if self.is_nan: return upper, FLAG_NV
        if self.is_inf: return lower if self.is_neg else upper, FLAG_NV
        v = self.to_int(rm)
        return (upper, FLAG_NV) if v>upper else (lower, FLAG_NV) if v<lower else (v, FLAG_NX*(v!=self.float))
    def to_int(self, rm=0):
        if rm==RM_RNE or rm==RM_RMM and int(self.float*2)!=self.float*2: return round(self.float)
        if rm==RM_RTZ: return int(self.float)
        if rm==RM_RDN: return math.floor(self.float)
        if rm==RM_RUP: return math.ceil(self.float)
        if rm==RM_RMM: return math.ceil(self.float) if self.float > 0 else int(self.float)  # RMM break tie away from zero
    def to_f32_and_flags(self, rm=0):
        if self.is_inf: return f32(f32.SIGN_BIT*self.is_neg | f32.EXP_MASK).float, 0
        if self.is_nan: return f32(f32.QNAN).float, FLAG_NV*self.is_snan
        r = f32.normalized(self.s, self.e, self.is_neg, rm)
        return r.float, r.flags
    def to_f64_and_flags(self, rm=0):
        if self.is_inf: return f64(f64.SIGN_BIT*self.is_neg | f64.EXP_MASK).float, 0
        if self.is_nan: return f64(f64.QNAN).float, FLAG_NV*self.is_snan
        r = f64.normalized(self.s, self.e, self.is_neg, rm)
        return r.float, r.flags

    @classmethod
    def div(cls, a, b, rm=0):
        a, b = cls(a), cls(b)
        flags = FLAG_NV*(a.is_snan or b.is_snan)
        if a.is_nan or b.is_nan: return cls(cls.QNAN, flags)
        if b.is_zero:
            if a.is_zero: return cls(cls.QNAN, FLAG_NV)
            else:
                if not a.is_inf: flags |= FLAG_DZ
                return cls(float('-inf'), flags) if a.is_neg != b.is_neg else cls(float('inf'), flags)
        if a.is_inf:
            if b.is_inf: return cls(cls.QNAN, FLAG_NV)
            return cls(float('-inf'), flags) if a.is_neg != b.is_neg else cls(float('inf'), flags)
        if b.is_inf: return cls(-0.0, flags) if a.is_neg != b.is_neg else cls(0.0, flags)
        a_s = a.s << (128-a.s.bit_length())
        b_s = b.s << (64-b.s.bit_length())
        r_s = a_s // b_s
        r_s |= r_s != -(a_s // -b_s)  # set LSB when ceil_div > floor_div. Fixes rounding and NX flag.
        r_e = a.e - b.e - 65 + r_s.bit_length()
        return cls.normalized(r_s, r_e, a.is_neg != b.is_neg, rm)

    @classmethod
    def mul(cls, a, b, rm=0):
        a, b = cls(a), cls(b)
        flags = FLAG_NV*(a.is_snan or b.is_snan)
        if a.is_nan or b.is_nan: return cls(cls.QNAN, flags)
        if a.is_inf or b.is_inf:
            if a.is_zero or b.is_zero: return cls(cls.QNAN, FLAG_NV)
            return cls(float('-inf'), flags) if a.is_neg != b.is_neg else cls(float('inf'), flags)
        if a.is_zero or b.is_zero: return cls(-0.0, flags) if a.is_neg != b.is_neg else cls(0.0, flags)
        r_s = a.s * b.s
        r_e = a.e + b.e + r_s.bit_length() - a.s.bit_length() - b.s.bit_length() + 1
        return cls.normalized(r_s, r_e, a.is_neg != b.is_neg, rm)

    @classmethod
    def add(cls, a, b, rm=0):
        a, b = cls(a), cls(b)
        flags = FLAG_NV*(a.is_snan or b.is_snan)
        if a.is_nan or b.is_nan: return cls(cls.QNAN, flags)
        if a.is_inf or b.is_inf:
            if a.is_inf and b.is_inf and a.is_neg != b.is_neg: return cls(cls.QNAN, FLAG_NV)
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
        return cls.normalized(s_s, s_e, s_sign, rm)

    @classmethod
    def mad(cls, a, b, c, rm=0, negate_product=False):
        a, b, c = cls(a), cls(b), cls(c)
        flags = FLAG_NV*(a.is_snan or b.is_snan or c.is_snan)
        if a.is_nan or b.is_nan: return cls(cls.QNAN, flags)
        if a.is_inf or b.is_inf:
            if a.is_zero or b.is_zero: return cls(cls.QNAN, FLAG_NV)
            if a.is_nan or b.is_nan or c.is_nan: return cls(cls.QNAN, flags)
            s_sign = a.is_neg != b.is_neg
            s_sign = s_sign != negate_product
            if c.is_inf and c.is_neg != s_sign: return cls(cls.QNAN, FLAG_NV)
            return cls(float('-inf'), flags) if s_sign else cls(float('inf'), flags)
        if a.is_nan or b.is_nan or c.is_nan: return cls(cls.QNAN, flags)
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
        return cls.normalized(s_s, s_e, s_sign, rm)

    @classmethod
    def sqrt(cls, a, rm=0):
        a = cls(a)
        if a.is_nan: return cls(cls.QNAN, FLAG_NV*a.is_snan)
        if a.is_zero: return cls(cls.SIGN_BIT*a.is_neg, FLAG_NV*a.is_snan)
        if a.is_neg: return cls(cls.QNAN, FLAG_NV)
        if a.is_inf: return cls(cls.EXP_MASK)  # inf
        a_s = a.s << (128-a.s.bit_length()+(a.e%2==0))
        r_s = math.isqrt(a_s)
        r_s |= r_s != (1+math.isqrt(a_s-1))  # set LSB when ceil_sqrt > floor_sqrt. Fixes rounding and NX flag.
        return cls.normalized(r_s, a.e//2, False, rm)

    def __repr__(self) -> str: return ('- ' if self.is_neg else '+ ') + f's: {self.s:b} e: {self.e} raw: {hex(self.raw)} value: {self.float}'

class f32(flt):
    FLEN      = 32
    TLEN      = 23  # number of trailing significand bits
    SIGN_BIT  = 1 << FLEN-1
    QUIET_BIT = 1 << TLEN-1
    ABS_MASK  = SIGN_BIT-1
    SIG_ONE   = 1 << TLEN
    TSIG_MASK = SIG_ONE-1
    EXP_MASK  = ABS_MASK ^ TSIG_MASK
    EXP_BIAS  = (1<<FLEN-TLEN-2)-1
    QNAN      = EXP_MASK|QUIET_BIT
    FMAX      = ABS_MASK ^ (1<<TLEN)
    def __init__(self, float_or_raw, flags=0):
        raw = zext(32, float_or_raw) if isinstance(float_or_raw, int) else struct.unpack('I', struct.pack('f', float_or_raw))[0]
        super().__init__(struct.unpack('f', struct.pack('I', raw))[0], raw, flags)

class f64(flt):
    FLEN      = 64
    TLEN      = 52  # number of trailing significand bits
    SIGN_BIT  = 1 << FLEN-1
    QUIET_BIT = 1 << TLEN-1
    ABS_MASK  = SIGN_BIT-1
    SIG_ONE   = 1 << TLEN
    TSIG_MASK = SIG_ONE-1
    EXP_MASK  = ABS_MASK ^ TSIG_MASK
    EXP_BIAS  = (1<<FLEN-TLEN-2)-1
    QNAN      = EXP_MASK|QUIET_BIT
    FMAX      = ABS_MASK ^ (1<<TLEN)
    def __init__(self, float_or_raw, flags=0):
        raw = zext(64, float_or_raw) if isinstance(float_or_raw, int) else struct.unpack('Q', struct.pack('d', float_or_raw))[0]
        super().__init__(struct.unpack('d', struct.pack('Q', raw))[0], raw, flags)

if __name__ == "__main__":
    p = [float(a) if '.' in a or 'inf' in a.lower() or 'nan' in a.lower() else int(a, 16) for a in sys.argv[1:]]
    print(f64(p[0]))
    #print(f64(p[1]))
    #print(f32(p[2]))
    r = f64.sqrt(p[0], rm=0)
    #r = f64.mul(p[0], p[1], rm=0)
    print(r, bin(r.flags))
