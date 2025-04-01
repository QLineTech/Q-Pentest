#!/usr/bin/env python3
# Bu program, DEX dosyalarını okuyup, okunabilir koda çevirir.
# Android uygulamalarının içindeki kodları analiz etmek için kullanılır.
# Zehra Kolsuz

import argparse  # Kullanıcıdan komutlar almamızı sağlar.
import struct   # Dosyadaki sayıları ve verileri doğru şekilde okumamıza yardım eder.
import os       # Dosyaları açmak ve kaydetmek gibi işlemler için kullanılır.
import sys      # Programı kapatmak veya hata mesajları göstermek için lazım.
import logging  # Program çalışırken neler olduğunu kullanıcıya haber verir.
from typing import List, Dict, Tuple  # Gerekli türleri açıkça belirtiyoruz (Any yerine _ kullanılmaz).
from concurrent.futures import ThreadPoolExecutor  # Birden fazla işi aynı anda yapmamızı sağlar.
from colorama import init, Fore, Style  # Çıktıları renkli yapar.

# Renkli terminal çıktıları için colorama başlatma
init()

# Logging ayarları
logging.basicConfig(level=logging.INFO, format=f"{Fore.BLUE}%(levelname)s{Style.RESET_ALL}: %(message)s")
logger = logging.getLogger(__name__)

# Özel hata sınıfı
class DexParseError(Exception):
    """DEX ayrıştırma hataları için özel istisna sınıfı."""
    pass

### Yardımcı Fonksiyonlar ###
def read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """ULEB128 formatında değişken uzunluklu tamsayıyı okur."""
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        result |= (byte & 0x7f) << shift
        offset += 1
        if not (byte & 0x80):
            break
        shift += 7
    return result, offset

def read_string(data: bytes, offset: int) -> Tuple[str, int]:
    """DEX string verisini UTF-8 olarak çözer."""
    length, offset = read_uleb128(data, offset)
    string_data = data[offset:offset + length].decode('utf-8', errors='replace')
    return string_data, offset + length

### DEX Ayrıştırma Fonksiyonları ###
def parse_header(data: bytes) -> Dict[str, int]:
    """DEX dosyasının başlığını ayrıştırır."""
    magic = data[:8]
    if magic[:4] != b'dex\n':
        raise DexParseError("Geçersiz DEX dosya formatı")
    return {
        'string_ids_size': struct.unpack('<I', data[56:60])[0],
        'string_ids_off': struct.unpack('<I', data[60:64])[0],
        'type_ids_size': struct.unpack('<I', data[64:68])[0],
        'type_ids_off': struct.unpack('<I', data[68:72])[0],
        'field_ids_size': struct.unpack('<I', data[80:84])[0],
        'field_ids_off': struct.unpack('<I', data[84:88])[0],
        'method_ids_size': struct.unpack('<I', data[88:92])[0],
        'method_ids_off': struct.unpack('<I', data[92:96])[0],
        'class_defs_size': struct.unpack('<I', data[96:100])[0],
        'class_defs_off': struct.unpack('<I', data[100:104])[0],
    }

def parse_strings(data: bytes, header: Dict[str, int]) -> List[str]:
    """String tablosunu paralel olarak ayrıştırır."""
    string_ids_off = header['string_ids_off']
    string_ids_size = header['string_ids_size']
    string_offsets = [struct.unpack('<I', data[string_ids_off + i * 4:string_ids_off + i * 4 + 4])[0] 
                      for i in range(string_ids_size)]
    strings = [None] * string_ids_size

    def process_string(idx: int):
        string_data, _ = read_string(data, string_offsets[idx])
        strings[idx] = string_data

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        executor.map(process_string, range(string_ids_size))
    
    return strings

def parse_types(data: bytes, header: Dict[str, int], strings: List[str]) -> List[str]:
    """Tip tablosunu ayrıştırır."""
    type_ids_off = header['type_ids_off']
    type_ids_size = header['type_ids_size']
    return [strings[struct.unpack('<I', data[type_ids_off + i * 4:type_ids_off + i * 4 + 4])[0]] 
            for i in range(type_ids_size)]

def parse_fields(data: bytes, header: Dict[str, int], strings: List[str], types: List[str]) -> List[Dict[str, str]]:
    """Alan (field) tablosunu ayrıştırır."""
    field_ids_off = header['field_ids_off']
    field_ids_size = header['field_ids_size']
    fields = []
    for i in range(field_ids_size):
        offset = field_ids_off + i * 8
        class_idx, type_idx, name_idx = struct.unpack('<HHI', data[offset:offset + 8])
        fields.append({
            'class': types[class_idx],
            'type': types[type_idx],
            'name': strings[name_idx]
        })
    return fields

def parse_methods(data: bytes, header: Dict[str, int], strings: List[str], types: List[str]) -> List[Dict[str, str]]:
    """Yöntem (method) tablosunu ayrıştırır."""
    method_ids_off = header['method_ids_off']
    method_ids_size = header['method_ids_size']
    methods = []
    for i in range(method_ids_size):
        offset = method_ids_off + i * 8
        class_idx, proto_idx, name_idx = struct.unpack('<HHI', data[offset:offset + 8])
        methods.append({
            'class': types[class_idx],
            'name': strings[name_idx],
            'proto_idx': proto_idx
        })
    return methods

def parse_classes(data: bytes, header: Dict[str, int], strings: List[str], types: List[str]) -> List[Dict[str, str]]:
    """Sınıf tanımlarını ayrıştırır."""
    class_defs_off = header['class_defs_off']
    class_defs_size = header['class_defs_size']
    classes = []
    for i in range(class_defs_size):
        start = class_defs_off + i * 32
        # Alt çizgi (_) kullanarak kullanılmayan değerleri açıkça belirtiyoruz.
        class_idx, _, superclass_idx, _, source_file_idx, _, class_data_off, _ = \
            struct.unpack('<IIIIIIII', data[start:start + 32])
        classes.append({
            'name': types[class_idx],
            'superclass': types[superclass_idx] if superclass_idx != 0xFFFFFFFF else None,
            'data_offset': class_data_off,
            'source_file': strings[source_file_idx] if source_file_idx != 0xFFFFFFFF else None
        })
    return classes

### Decompile İşlemi ###
def function(args, types):
    return f'v{args[0]} = ({types[args[1]}}) v{args[0]};'


OPCODE_MAP = {
    # NOP ve Dönüş İşlemleri
    0x00: ('nop', lambda args, _: ''),
    0x0e: ('return-void', lambda args, _: 'return;'),
    0x0f: ('return', lambda args, _: f'return v{args[0]};'),
    0x10: ('return-wide', lambda args, _: f'return v{args[0]};  // wide'),
    0x11: ('return-object', lambda args, _: f'return v{args[0]};  // object'),

    # Temel Taşıma İşlemleri
    0x01: ('move', lambda args, _: f'v{args[0]} = v{args[1]};'),
    0x02: ('move/from16', lambda args, _: f'v{args[0]} = v{args[1]};'),
    0x03: ('move/16', lambda args, _: f'v{args[0]} = v{args[1]};'),
    0x04: ('move-wide', lambda args, _: f'v{args[0]} = v{args[1]};  // wide'),
    0x05: ('move-wide/from16', lambda args, _: f'v{args[0]} = v{args[1]};  // wide'),
    0x06: ('move-wide/16', lambda args, _: f'v{args[0]} = v{args[1]};  // wide'),
    0x07: ('move-object', lambda args, _: f'v{args[0]} = v{args[1]};  // object'),
    0x08: ('move-object/from16', lambda args, _: f'v{args[0]} = v{args[1]};  // object'),
    0x09: ('move-object/16', lambda args, _: f'v{args[0]} = v{args[1]};  // object'),

    # Method Dönüş Değeri Taşıma
    0x0a: ('move-result', lambda args, _: f'v{args[0]} = result;'),
    0x0b: ('move-result-wide', lambda args, _: f'v{args[0]} = result;  // wide'),
    0x0c: ('move-result-object', lambda args, _: f'v{args[0]} = result;  // object'),
    0x0d: ('move-exception', lambda args, _: f'v{args[0]} = exception;'),

    # Sabit Yükleme İşlemleri
    0x12: ('const/4', lambda args, _: f'v{args[0]} = {args[1] & 0xF};'),
    0x13: ('const/16', lambda args, val: f'v{args[0]} = {val};'),  # val parametresi eklenecek
    0x14: ('const', lambda args, val: f'v{args[0]} = {val};'),  # val parametresi eklenecek
    0x15: ('const/high16', lambda args, val: f'v{args[0]} = {val << 16};'),  # val parametresi eklenecek
    0x16: ('const-wide/16', lambda args, val: f'v{args[0]} = {val};  // wide'),
    0x17: ('const-wide/32', lambda args, val: f'v{args[0]} = {val};  // wide'),
    0x18: ('const-wide', lambda args, val: f'v{args[0]} = {val};  // wide'),
    0x19: ('const-wide/high16', lambda args, val: f'v{args[0]} = {val << 48};  // wide'),
    0x1a: ('const-string', lambda args, strings: f'v{args[0]} = "{strings[args[1]]}";'),
    0x1b: ('const-string/jumbo', lambda args, strings: f'v{args[0]} = "{strings[args[1]]}";'),
    0x1c: ('const-class', lambda args, types: f'v{args[0]} = {types[args[1]]}.class;'),

    # Alan (Field) İşlemleri
    0x52: ('iget', lambda args, fields: f'v{args[0]} = {fields[args[2]]["name"]};'),
    0x53: ('iget-wide', lambda args, fields: f'v{args[0]} = {fields[args[2]]["name"]};  // wide'),
    0x54: ('iget-object', lambda args, fields: f'v{args[0]} = {fields[args[2]]["name"]};  // object'),
    0x55: ('iget-boolean', lambda args, fields: f'v{args[0]} = {fields[args[2]]["name"]};  // boolean'),
    0x56: ('iget-byte', lambda args, fields: f'v{args[0]} = {fields[args[2]]["name"]};  // byte'),
    0x57: ('iget-char', lambda args, fields: f'v{args[0]} = {fields[args[2]]["name"]};  // char'),
    0x58: ('iget-short', lambda args, fields: f'v{args[0]} = {fields[args[2]]["name"]};  // short'),
    0x59: ('iput', lambda args, fields: f'{fields[args[2]]["name"]} = v{args[0]};'),
    0x5a: ('iput-wide', lambda args, fields: f'{fields[args[2]]["name"]} = v{args[0]};  // wide'),
    0x5b: ('iput-object', lambda args, fields: f'{fields[args[2]]["name"]} = v{args[0]};  // object'),
    0x5c: ('iput-boolean', lambda args, fields: f'{fields[args[2]]["name"]} = v{args[0]};  // boolean'),
    0x5d: ('iput-byte', lambda args, fields: f'{fields[args[2]]["name"]} = v{args[0]};  // byte'),
    0x5e: ('iput-char', lambda args, fields: f'{fields[args[2]]["name"]} = v{args[0]};  // char'),
    0x5f: ('iput-short', lambda args, fields: f'{fields[args[2]]["name"]} = v{args[0]};  // short'),

    0x60: ('sget', lambda args, fields: f'v{args[0]} = {fields[args[1]]["name"]};  // static'),
    0x61: ('sget-wide', lambda args, fields: f'v{args[0]} = {fields[args[1]]["name"]};  // static wide'),
    0x62: ('sget-object', lambda args, fields: f'v{args[0]} = {fields[args[1]]["name"]};  // static object'),
    0x63: ('sget-boolean', lambda args, fields: f'v{args[0]} = {fields[args[1]]["name"]};  // static boolean'),
    0x64: ('sget-byte', lambda args, fields: f'v{args[0]} = {fields[args[1]]["name"]};  // static byte'),
    0x65: ('sget-char', lambda args, fields: f'v{args[0]} = {fields[args[1]]["name"]};  // static char'),
    0x66: ('sget-short', lambda args, fields: f'v{args[0]} = {fields[args[1]]["name"]};  // static short'),
    0x67: ('sput', lambda args, fields: f'{fields[args[1]]["name"]} = v{args[0]};  // static'),
    0x68: ('sput-wide', lambda args, fields: f'{fields[args[1]]["name"]} = v{args[0]};  // static wide'),
    0x69: ('sput-object', lambda args, fields: f'{fields[args[1]]["name"]} = v{args[0]};  // static object'),
    0x6a: ('sput-boolean', lambda args, fields: f'{fields[args[1]]["name"]} = v{args[0]};  // static boolean'),
    0x6b: ('sput-byte', lambda args, fields: f'{fields[args[1]]["name"]} = v{args[0]};  // static byte'),
    0x6c: ('sput-char', lambda args, fields: f'{fields[args[1]]["name"]} = v{args[0]};  // static char'),
    0x6d: ('sput-short', lambda args, fields: f'{fields[args[1]]["name"]} = v{args[0]};  // static short'),

    # Method Çağrı İşlemleri
    0x6e: ('invoke-virtual', lambda args, methods: f'v{args[1]}.{methods[args[0]]["name"]}(...);'),
    0x6f: ('invoke-super', lambda args, methods: f'super.{methods[args[0]]["name"]}(...);'),
    0x70: ('invoke-direct', lambda args, methods: f'{methods[args[0]]["name"]}(...);'),
    0x71: ('invoke-static', lambda args, methods: f'{methods[args[0]]["class"]}.{methods[args[0]]["name"]}(...);'),
    0x72: ('invoke-interface', lambda args, methods: f'v{args[1]}.{methods[args[0]]["name"]}(...);  // interface'),

    0x74: ('invoke-virtual/range', lambda args, methods: f'v{args[1]}.{methods[args[0]]["name"]}(...);  // range'),
    0x75: ('invoke-super/range', lambda args, methods: f'super.{methods[args[0]]["name"]}(...);  // range'),
    0x76: ('invoke-direct/range', lambda args, methods: f'{methods[args[0]]["name"]}(...);  // range'),
    0x77: ('invoke-static/range',
           lambda args, methods: f'{methods[args[0]]["class"]}.{methods[args[0]]["name"]}(...);  // range'),
    0x78: ('invoke-interface/range',
           lambda args, methods: f'v{args[1]}.{methods[args[0]]["name"]}(...);  // interface, range'),

    # Aritmetik ve Mantıksal İşlemler
    0x90: ('add-int', lambda args, _: f'v{args[0]} = v{args[1]} + v{args[2]};'),
    0x91: ('sub-int', lambda args, _: f'v{args[0]} = v{args[1]} - v{args[2]};'),
    0x92: ('mul-int', lambda args, _: f'v{args[0]} = v{args[1]} * v{args[2]};'),
    0x93: ('div-int', lambda args, _: f'v{args[0]} = v{args[1]} / v{args[2]};'),
    0x94: ('rem-int', lambda args, _: f'v{args[0]} = v{args[1]} % v{args[2]};'),
    0x95: ('and-int', lambda args, _: f'v{args[0]} = v{args[1]} & v{args[2]};'),
    0x96: ('or-int', lambda args, _: f'v{args[0]} = v{args[1]} | v{args[2]};'),
    0x97: ('xor-int', lambda args, _: f'v{args[0]} = v{args[1]} ^ v{args[2]};'),
    0x98: ('shl-int', lambda args, _: f'v{args[0]} = v{args[1]} << v{args[2]};'),
    0x99: ('shr-int', lambda args, _: f'v{args[0]} = v{args[1]} >> v{args[2]};'),
    0x9a: ('ushr-int', lambda args, _: f'v{args[0]} = v{args[1]} >>> v{args[2]};'),

    # İki Kaynaklı Aritmetik (Two-address Arithmetic)
    0xb0: ('add-int/2addr', lambda args, _: f'v{args[0]} += v{args[1]};'),
    0xb1: ('sub-int/2addr', lambda args, _: f'v{args[0]} -= v{args[1]};'),
    0xb2: ('mul-int/2addr', lambda args, _: f'v{args[0]} *= v{args[1]};'),
    0xb3: ('div-int/2addr', lambda args, _: f'v{args[0]} /= v{args[1]};'),
    0xb4: ('rem-int/2addr', lambda args, _: f'v{args[0]} %= v{args[1]};'),
    0xb5: ('and-int/2addr', lambda args, _: f'v{args[0]} &= v{args[1]};'),
    0xb6: ('or-int/2addr', lambda args, _: f'v{args[0]} |= v{args[1]};'),
    0xb7: ('xor-int/2addr', lambda args, _: f'v{args[0]} ^= v{args[1]};'),
    0xb8: ('shl-int/2addr', lambda args, _: f'v{args[0]} <<= v{args[1]};'),
    0xb9: ('shr-int/2addr', lambda args, _: f'v{args[0]} >>= v{args[1]};'),
    0xba: ('ushr-int/2addr', lambda args, _: f'v{args[0]} >>>= v{args[1]};'),

    # Sabitli Aritmetik (Lit Arithmetic)
    0xd0: ('add-int/lit16', lambda args, val: f'v{args[0]} = v{args[1]} + {val};'),
    0xd1: ('sub-int/lit16', lambda args, val: f'v{args[0]} = v{args[1]} - {val};'),
    0xd2: ('mul-int/lit16', lambda args, val: f'v{args[0]} = v{args[1]} * {val};'),
    0xd3: ('div-int/lit16', lambda args, val: f'v{args[0]} = v{args[1]} / {val};'),
    0xd4: ('rem-int/lit16', lambda args, val: f'v{args[0]} = v{args[1]} % {val};'),
    0xd5: ('and-int/lit16', lambda args, val: f'v{args[0]} = v{args[1]} & {val};'),
    0xd6: ('or-int/lit16', lambda args, val: f'v{args[0]} = v{args[1]} | {val};'),
    0xd7: ('xor-int/lit16', lambda args, val: f'v{args[0]} = v{args[1]} ^ {val};'),

    # 8-bit Sabitli Aritmetik
    0xd8: ('add-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} + {val};'),
    0xd9: ('sub-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} - {val};'),
    0xda: ('mul-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} * {val};'),
    0xdb: ('div-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} / {val};'),
    0xdc: ('rem-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} % {val};'),
    0xdd: ('and-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} & {val};'),
    0xde: ('or-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} | {val};'),
    0xdf: ('xor-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} ^ {val};'),
    0xe0: ('shl-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} << {val};'),
    0xe1: ('shr-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} >> {val};'),
    0xe2: ('ushr-int/lit8', lambda args, val: f'v{args[0]} = v{args[1]} >>> {val};'),

    # Karşılaştırma İşlemleri
    0x2d: ('cmpl-float',
           lambda args, _: f'v{args[0]} = (v{args[1]} < v{args[2]}) ? -1 : ((v{args[1]} == v{args[2]}) ? 0 : 1);'),
    0x2e: ('cmpg-float',
           lambda args, _: f'v{args[0]} = (v{args[1]} > v{args[2]}) ? 1 : ((v{args[1]} == v{args[2]}) ? 0 : -1);'),
    0x2f: ('cmpl-double', lambda args,
                                 _: f'v{args[0]} = (v{args[1]} < v{args[2]}) ? -1 : ((v{args[1]} == v{args[2]}) ? 0 : 1);  // double'),
    0x30: ('cmpg-double', lambda args,
                                 _: f'v{args[0]} = (v{args[1]} > v{args[2]}) ? 1 : ((v{args[1]} == v{args[2]}) ? 0 : -1);  // double'),
    0x31: ('cmp-long', lambda args,
                              _: f'v{args[0]} = (v{args[1]} == v{args[2]}) ? 0 : ((v{args[1]} < v{args[2]}) ? -1 : 1);  // long'),

    # Dallanma İşlemleri (Branch/Jump)
    0x32: ('if-eq', lambda args, _: f'if (v{args[0]} == v{args[1]}) goto label_{args[2]};'),
    0x33: ('if-ne', lambda args, _: f'if (v{args[0]} != v{args[1]}) goto label_{args[2]};'),
    0x34: ('if-lt', lambda args, _: f'if (v{args[0]} < v{args[1]}) goto label_{args[2]};'),
    0x35: ('if-ge', lambda args, _: f'if (v{args[0]} >= v{args[1]}) goto label_{args[2]};'),
    0x36: ('if-gt', lambda args, _: f'if (v{args[0]} > v{args[1]}) goto label_{args[2]};'),
    0x37: ('if-le', lambda args, _: f'if (v{args[0]} <= v{args[1]}) goto label_{args[2]};'),

    0x38: ('if-eqz', lambda args, _: f'if (v{args[0]} == 0) goto label_{args[1]};'),
    0x39: ('if-nez', lambda args, _: f'if (v{args[0]} != 0) goto label_{args[1]};'),
    0x3a: ('if-ltz', lambda args, _: f'if (v{args[0]} < 0) goto label_{args[1]};'),
    0x3b: ('if-gez', lambda args, _: f'if (v{args[0]} >= 0) goto label_{args[1]};'),
    0x3c: ('if-gtz', lambda args, _: f'if (v{args[0]} > 0) goto label_{args[1]};'),
    0x3d: ('if-lez', lambda args, _: f'if (v{args[0]} <= 0) goto label_{args[1]};'),

    # Koşulsuz Dallanma
    0x28: ('goto', lambda args, _: f'goto label_{args[0]};'),
    0x29: ('goto/16', lambda args, _: f'goto label_{args[0]};  // 16-bit offset'),
    0x2a: ('goto/32', lambda args, _: f'goto label_{args[0]};  // 32-bit offset'),

    # Array İşlemleri
    0x44: ('aget', lambda args, _: f'v{args[0]} = v{args[1]}[v{args[2]}];'),
    0x45: ('aget-wide', lambda args, _: f'v{args[0]} = v{args[1]}[v{args[2]}];  // wide'),
    0x46: ('aget-object', lambda args, _: f'v{args[0]} = v{args[1]}[v{args[2]}];  // object'),
    0x47: ('aget-boolean', lambda args, _: f'v{args[0]} = v{args[1]}[v{args[2]}];  // boolean'),
    0x48: ('aget-byte', lambda args, _: f'v{args[0]} = v{args[1]}[v{args[2]}];  // byte'),
    0x49: ('aget-char', lambda args, _: f'v{args[0]} = v{args[1]}[v{args[2]}];  // char'),
    0x4a: ('aget-short', lambda args, _: f'v{args[0]} = v{args[1]}[v{args[2]}];  // short'),

    0x4b: ('aput', lambda args, _: f'v{args[1]}[v{args[2]}] = v{args[0]};'),
    0x4c: ('aput-wide', lambda args, _: f'v{args[1]}[v{args[2]}] = v{args[0]};  // wide'),
    0x4d: ('aput-object', lambda args, _: f'v{args[1]}[v{args[2]}] = v{args[0]};  // object'),
    0x4e: ('aput-boolean', lambda args, _: f'v{args[1]}[v{args[2]}] = v{args[0]};  // boolean'),
    0x4f: ('aput-byte', lambda args, _: f'v{args[1]}[v{args[2]}] = v{args[0]};  // byte'),
    0x50: ('aput-char', lambda args, _: f'v{args[1]}[v{args[2]}] = v{args[0]};  // char'),
    0x51: ('aput-short', lambda args, _: f'v{args[1]}[v{args[2]}] = v{args[0]};  // short'),

    # Yaratma İşlemleri (Instantiation)
    0x22: ('new-instance', lambda args, types: f'v{args[0]} = new {types[args[1]]};'),
    0x23: ('new-array', lambda args, types: f'v{args[0]} = new {types[args[2]]}[v{args[1]}];'),

    # Tür Çevirme ve Kontrol İşlemleri
    0x20: ('instance-of', lambda args, types: f'v{args[0]} = (v{args[1]} instanceof {types[args[2]]});'),
    0x21: ('check-cast', function),

    # Monitor İşlemleri (Synchronization)
    0x1d: ('monitor-enter', lambda args, _: f'synchronized(v{args[0]}) {{'),
    0x1e: ('monitor-exit', lambda args, _: f'}}  // end synchronized'),

    # Exception Handling
    0x27: ('throw', lambda args, _: f'throw v{args[0]};'),

    # Debugger İlgili
    0x0a: ('packed-switch', lambda args, _: f'switch(v{args[0]}) {{  // packed'),
    0x0b: ('sparse-switch', lambda args, _: f'switch(v{args[0]}) {{  // sparse'),
    0x0c: ('array-data', lambda args, _: f'// array data follows'),

    # Diğer İşlemler
    0x26: ('fill-array-data', lambda args, _: f'// fill array with data'),
    0x25: ('filled-new-array', lambda args, types: f'new {types[args[0]]}{{...}};'),
    0x24: ('filled-new-array/range', lambda args, types: f'new {types[args[0]]}{{...}};  // range'),
}

def decompile_method_code(data: bytes, offset: int, strings: List[str], fields: List[Dict[str, str]], methods: List[Dict[str, str]]) -> List[str]:
    """Yöntem kodunu Dalvik bytecode'dan Java'ya çevirir."""
    if offset == 0:
        return []
    # Alt çizgi (_) ile kullanılmayan değerleri açıkça belirtiyoruz.
    registers_size, _, _, _, _, insns_size = struct.unpack('<HHHHII', data[offset:offset + 16])
    insns_offset = offset + 16
    code = []
    pc = 0
    while pc < insns_size * 2:
        opcode = data[insns_offset + pc]
        if opcode not in OPCODE_MAP:
            code.append(f'// Unknown opcode: 0x{opcode:02x}')
            pc += 2
            continue
        name, handler = OPCODE_MAP[opcode]
        args = struct.unpack('<BB', data[insns_offset + pc:insns_offset + pc + 2])
        pc += 2
        code.append(handler(args, strings if 'const-string' in name else methods))
    return code

### Ana Fonksiyon ###
def main():
    parser = argparse.ArgumentParser(description="DEX Decompiler")
    parser.add_argument("--input", required=True, help="Giriş DEX dosyası")
    parser.add_argument("--output", default="output", help="Çıktı dizini")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        logger.error(f"Dosya bulunamadı: {args.input}")
        sys.exit(1)
    os.makedirs(args.output, exist_ok=True)

    with open(args.input, "rb") as f:
        data = f.read()

    try:
        header = parse_header(data)
        strings = parse_strings(data, header)
        types = parse_types(data, header, strings)
        fields = parse_fields(data, header, strings, types)
        methods = parse_methods(data, header, strings, types)
        classes = parse_classes(data, header, strings, types)

        # Decompilation
        decompiled = {}
        for cls in classes:
            code = decompile_method_code(data, cls['data_offset'], strings, fields, methods)
            decompiled[cls['name']] = code

        # Çıktı dosyası
        with open(os.path.join(args.output, "decompiled.txt"), "w") as out_file:
            for cls_name, code in decompiled.items():
                out_file.write(f"Class: {cls_name}\n")
                out_file.write("{\n")
                for line in code:
                    out_file.write(f"  {line}\n")
                out_file.write("}\n\n")
        logger.info(f"Decompile tamamlandı: {args.output}/decompiled.txt")

    except DexParseError as e:
        logger.error(f"DEX ayrıştırma hatası: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Beklenmedik hata: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
