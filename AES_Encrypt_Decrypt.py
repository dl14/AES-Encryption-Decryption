# Helper Functions

# Function: Calculate the true length of the binary value (disregard leading 0's)
# Input: str_1 (binary string)
# Output: length (integer)
def calc_length(str_1):
    length = len(str_1)
    for i in range(0, len(str_1)):
        if(c2n(str_1[i]) == 0):
            length -= 1
        else:
            break
    return length

# Function: convert char to number
# Input: char
# Output: integer
def c2n(char):
    return (ord(char) - 48)

# Function: reduces binary string bin by mod b
# Input: bin (binary string), b (binary string) - defaulted as the AES polynoial
# Output: binary string (reduced)
def reduce_modP(bin, b = '100011011'):
    while (calc_length(bin) >= calc_length(b)):
        new_p = b.ljust(len(bin), '0')
        # print('P: {}'.format(new_p))
        new_ans = ''
        for i in range(calc_length(bin) - 1, -1, -1):
            sum = c2n(bin[i]) ^ c2n(new_p[i])
            new_ans = new_ans.rjust(len(new_ans) + 1, chr(sum + 48))
        bin = new_ans
        bin = bin.lstrip('0')
    return(bin)

# Function: multiply hex strings x and y mod b
# Input: x (hex string), y (hex string), b (binary)
# Output: hex string
def Multiply(x, y, b = '100011011'):
    if(x == '00'):
        ans = hex2bin('00')
    elif(y == '00'):
        ans = hex2bin('00')
    else:
        ans = bin_mult(hex2bin(x), hex2bin(y))
    ans = reduce_modP(ans)
    return bin2hex(ans)

# Function: binary multiplication
# Input: binary strings str_1, str_2
# Output: binary string ans
def bin_mult(str_1, str_2):
    add_values = []
    ans = ''
    # shift str_1 everytime you see a 1 in str_2
    for i in range(len(str_2) - 1, -1, -1):
        if(c2n(str_2[i]) == 1):
            add_values.append(str_1.ljust(len(str_1) + (len(str_2) - 1 - i), '0'))
    max_len = len(max(add_values))

    # align all the values that will need to be XOR'd
    for j in range(0, len(add_values)):
        add_values[j] = add_values[j].rjust(max_len, '0')

    for l in range(max_len - 1, -1, -1):
        sum = 0
        for m in range(0, len(add_values)):
            sum ^= c2n(add_values[m][l])
        ans = ans.rjust(len(ans) + 1, chr(sum + 48))
    return ans

# Function: binary addition
# Input: binary strings str_1, str_2
# Output: binary string answer
def bin_add(str_1, str_2):
    ans = ''
    if(str_1 == ''):
        return str_2
    if(str_2 == ''):
        return str_1
    if(calc_length(str_1) < calc_length(str_2)):
        temp = str_1
        str_1 = str_2
        str_2 = temp
    j = 0
    for i in range(calc_length(str_2) - 1, -1, -1):
        ans = chr(((c2n(str_2[i]) + c2n(str_1[calc_length(str_1) - 1 - j])) % 2) + 48) + ans
        j += 1
    answer = str_1[:-calc_length(str_2)] + ans
    if(answer == ''):
        answer = '0'
    return answer

# Function: convert hex to binary
# Input: hex string
# Output: hex string
def hex2bin(hex):
    return "{0:0>2b}".format(int(hex, 16))

# Function: convert binary to hex
# Input: binary string
# Output: hex string
def bin2hex(bin):
    return "{0:0>2X}".format(int(bin, 2))

# AES Functions

# Function: rotates a four byte string to the left with wrapping
# Input: fourByteString (hex string)
# Output: hex string
def rotateLeft(fourByteString):
    byteList = [fourByteString[i:i + 2] for i in range(0, len(fourByteString), 2)]
    byteList2 = byteList[1:4]
    byteList2.append(byteList[0])
    return ''.join(byteList2)

# Function: xor two binary strings
# Note: originally the function was meant to just xor two byte's, however I added ans_length
#       to indicate the binary length of the answer and inputs that need to be xor'd
# Input: Byte1 (hex string), Byte2 (binary string), ans_length (integer)
# Output: hex string
def xor(byte1, byte2, ans_length = 8):
    byte1 = list(hex2bin(byte1).rjust(ans_length, '0'))
    byte2 = list(byte2.rjust(ans_length, '0'))
    ans = []
    for i in range(0, len(byte1)):
        ans.append(chr(c2n(byte1[i]) ^ c2n(byte2[i]) + 48))
    ans = ''.join(ans)
    ans = bin2hex(ans)
    ans = ans.rjust(8, '0')
    return ans


# Function: round constant portion of AES key expansion
# Input: fourByteString (hex string), i (integer which serves as a counter),
#        b (binary string which is the base polynomial)
# Output: hex string
def RCon(fourByteString, i, b = '100011011'):
    poly = list('00000000')
    poly_string = ''
    # reduce mod P if i > 7
    if(i > 7):
        poly_string = poly_string.rjust(i + 1, '0')
        poly = list(poly_string)
        poly[0] = '1'
        poly = ''.join(poly)
        poly = reduce_modP(poly).rjust(8, '0')
    else:
        poly[len(poly) - 1 - i] = '1'
        poly = ''.join(poly)
    firstByte = xor(fourByteString[:2], poly).lstrip('0').rjust(2, '0')
    byteList = [fourByteString[i:i + 2] for i in range(0, len(fourByteString), 2)]
    byteList[0] = firstByte
    return ''.join(byteList)

# Variable: sbox_table
# Use: Provides a 2D array for the sbox of AES. The byte '00' translates to '63' etc.
sbox_table = [
        ['63', '7C', '77', '7B', 'F2', '6B', '6F', 'C5', '30', '01', '67', '2B', 'FE', 'D7', 'AB', '76'],
        ['CA', '82', 'C9', '7D', 'FA', '59', '47', 'F0', 'AD', 'D4', 'A2', 'AF', '9C', 'A4', '72', 'C0'],
        ['B7', 'FD', '93', '26', '36', '3F', 'F7', 'CC', '34', 'A5', 'E5', 'F1', '71', 'D8', '31', '15'],
        ['04', 'C7', '23', 'C3', '18', '96', '05', '9A', '07', '12', '80', 'E2', 'EB', '27', 'B2', '75'],
        ['09', '83', '2C', '1A', '1B', '6E', '5A', 'A0', '52', '3B', 'D6', 'B3', '29', 'E3', '2F', '84'],
        ['53', 'D1', '00', 'ED', '20', 'FC', 'B1', '5B', '6A', 'CB', 'BE', '39', '4A', '4C', '58', 'CF'],
        ['D0', 'EF', 'AA', 'FB', '43', '4D', '33', '85', '45', 'F9', '02', '7F', '50', '3C', '9F', 'A8'],
        ['51', 'A3', '40', '8F', '92', '9D', '38', 'F5', 'BC', 'B6', 'DA', '21', '10', 'FF', 'F3', 'D2'],
        ['CD', '0C', '13', 'EC', '5F', '97', '44', '17', 'C4', 'A7', '7E', '3D', '64', '5D', '19', '73'],
        ['60', '81', '4F', 'DC', '22', '2A', '90', '88', '46', 'EE', 'B8', '14', 'DE', '5E', '0B', 'DB'],
        ['E0', '32', '3A', '0A', '49', '06', '24', '5C', 'C2', 'D3', 'AC', '62', '91', '95', 'E4', '79'],
        ['E7', 'C8', '37', '6D', '8D', 'D5', '4E', 'A9', '6C', '56', 'F4', 'EA', '65', '7A', 'AE', '08'],
        ['BA', '78', '25', '2E', '1C', 'A6', 'B4', 'C6', 'E8', 'DD', '74', '1F', '4B', 'BD', '8B', '8A'],
        ['70', '3E', 'B5', '66', '48', '03', 'F6', '0E', '61', '35', '57', 'B9', '86', 'C1', '1D', '9E'],
        ['E1', 'F8', '98', '11', '69', 'D9', '8E', '94', '9B', '1E', '87', 'E9', 'CE', '55', '28', 'DF'],
        ['8C', 'A1', '89', '0D', 'BF', 'E6', '42', '68', '41', '99', '2D', '0F', 'B0', '54', 'BB', '16']
    ]

def sbox(byte):
    first4bits = int(byte[:1], 16)
    sec4bits = int(byte[1:2], 16)

    ans = sbox_table[first4bits][sec4bits]
    return (ans)

def invSbox(byte):
    x = [x for x in sbox_table if byte in x][0]
    index_x = sbox_table.index(x)
    index_y = x.index(byte)
    chrx = hex(index_x).split('x')[-1]
    chry = hex(index_y).split('x')[-1]
    return((chrx+chry).upper())

# Function: performs shift rows portion of AES
# Input: fourByfourList (a 4x4 list with a byte in each position)
# Output: a 4x4 list with a byte in each position
def shiftRows(fourByfourList):
    # do nothing to row 0

    # shift row 1 by one position
    fourByfourList[1].insert(3, fourByfourList[1].pop(0))

    # shift row 2 by two positions
    fourByfourList[2].insert(3, fourByfourList[2].pop(0))
    fourByfourList[2].insert(3, fourByfourList[2].pop(0))

    # shift row 3 by three positions
    fourByfourList[3].insert(3, fourByfourList[3].pop(0))
    fourByfourList[3].insert(3, fourByfourList[3].pop(0))
    fourByfourList[3].insert(3, fourByfourList[3].pop(0))

    return fourByfourList

def invShiftRows(fourByfourList):
    fourByfourList[1].insert(3, fourByfourList[1].pop(0))
    fourByfourList[1].insert(3, fourByfourList[1].pop(0))
    fourByfourList[1].insert(3, fourByfourList[1].pop(0))

    fourByfourList[2].insert(3, fourByfourList[2].pop(0))
    fourByfourList[2].insert(3, fourByfourList[2].pop(0))

    fourByfourList[3].insert(3, fourByfourList[3].pop(0))

    return fourByfourList

# Function: performs mix columns step in AES key expansion
# Input: fourByteString (hex string)
# Output: hex string
def mixCols(fourByteString):
    byteList = [fourByteString[i:i + 2] for i in range(0, len(fourByteString), 2)]
    rows = []

    for i in range(0, 4):
        # select bytes
        byte_s0 = byteList[i].rjust(2, '0')
        byte_s1 = byteList[(i + 1) % 4].rjust(2, '0')
        byte_s2 = byteList[(i + 2) % 4].rjust(2, '0')
        byte_s3 = byteList[(i + 3) % 4].rjust(2, '0')
        # matrix multiplication
        m0 = Multiply('02', byte_s0)
        m1 = Multiply('03', byte_s1)
        m2 = Multiply('01', byte_s2)
        m3 = Multiply('01', byte_s3)
        # add previous values
        a0 = bin_add(hex2bin(m0).lstrip('0'), hex2bin(m1).lstrip('0'))
        a1 = bin_add(hex2bin(m2).lstrip('0'), hex2bin(m3).lstrip('0'))

        f0 = bin2hex(bin_add(a0.lstrip('0'), a1.lstrip('0')))
        rows.append(f0)

    return ''.join(rows)

def invMixCols(fourByteString):
    byteList = [fourByteString[i:i + 2] for i in range(0, len(fourByteString), 2)]
    rows = []

    for i in range(0, 4):
        byte_s0 = byteList[i].rjust(2, '0')
        byte_s1 = byteList[(i + 1) % 4].rjust(2, '0')
        byte_s2 = byteList[(i + 2) % 4].rjust(2, '0')
        byte_s3 = byteList[(i + 3) % 4].rjust(2, '0')

        # add these values
        m0 = Multiply('0E', byte_s0)
        m1 = Multiply('0B', byte_s1)
        m2 = Multiply('0D', byte_s2)
        m3 = Multiply('09', byte_s3)

        a0 = bin_add(hex2bin(m0).lstrip('0'), hex2bin(m1).lstrip('0'))
        a1 = bin_add(hex2bin(m2).lstrip('0'), hex2bin(m3).lstrip('0'))

        f0 = bin2hex(bin_add(a0.lstrip('0'), a1.lstrip('0')))
        rows.append(f0)

    return ''.join(rows)


# temp1 is a 4 byte hex decimal formatted string
def key_exp_core(temp1, i):
    # rotate left
    rotated_temp = rotateLeft(temp1)

    # s box
    sb = []
    for j in range(0, 8, 2):
        s_b = sbox(rotated_temp[j : j + 2])
        sb.append(s_b)
    sb = ''.join(sb)

    # round constant
    first_four = RCon(sb, i)
    sb = first_four.lstrip('0').rjust(8, '0')

    return sb

# initial_key (hex string)
def key_exp(initial_key, length):
    expansion_key = []
    expansion_key.append(initial_key)
    counter = 0
    range_bytes = 4
    end_key_cout = 11
    last_bytes_of_expKey = 16
    if(length == 128):
        range_bytes = 4
        end_key_cout = 176 #11
        last_bytes_of_expKey = 16
    elif(length == 192):
        range_bytes = 6
        end_key_cout = 208 #13
        last_bytes_of_expKey = 24
    elif(length == 256):
        range_bytes = 8
        end_key_cout = 240 #15
        last_bytes_of_expKey = 32

    exp_key = initial_key
    while ((len(exp_key) / 2) < end_key_cout):
        for i in range(0, range_bytes):
            # temp1 = first four bytes of expansion key
            temp1 = exp_key[len(exp_key) - 8 : len(exp_key)]
            if(i == 0):
                temp1 = key_exp_core(temp1, counter)
                counter += 1 # increment counter for RCon step in core
            if(i == 4 and length == 256):
                sb = []
                for j in range(0, 8, 2):
                    s_b = sbox(temp1[j: j + 2])
                    sb.append(s_b)
                temp1 = ''.join(sb)
            # temp2 = last x number of bytes of expansion Key
            temp2 = exp_key[len(exp_key) - (last_bytes_of_expKey * 2) : len(exp_key)]
            # temp2 = first 4 bytes of temp2
            temp2 = temp2[0:8]
            # append (temp1 xor temp2) to expansion_key
            exp_key += xor(temp1, hex2bin(temp2), 32)
            if(len(exp_key) == (end_key_cout * 2)):
                break
    final_key = []
    # create list of 16 byte keys
    for j in range(0, len(exp_key) - 1, 32):
        final_key.append(exp_key[j:j+32])
    return final_key

def subBytes(full_128):
    sb = []
    for i in range(0, 32, 2):
        sb.append(sbox(full_128[i: i + 2]))
    return ''.join(sb)

def invSubBytes(full_128):
    sb = []
    for i in range(0, 32, 2):
        sb.append(invSbox(full_128[i: i + 2]))
    return ''.join(sb)

# Function: Encrypt plaintext using AES
# Input: plaintext (hex string), key0 (hex string)
# Output: ciphertext (hex string)
def AES_encryption(plaintext_orig, key0, ecb = True):
    if not plaintext_orig:
        print("empty plaintext")
    else:
        # check length of initial key
        if (len(key0) != 32 and len(key0) != 48 and len(key0) != 64):
            return

        if((len(plaintext_orig) * 4) % 128 != 0):
            plaintext_orig = plaintext_orig.ljust(len(plaintext_orig) + (32 - (len(plaintext_orig) % 32)), '0')

        final_ciphertext = []
        for block_counter in range(0, len(plaintext_orig) - 1, 32):
            keys = key_exp(key0, len(key0) * 4)

            # check the # of keys that were produced from key expansion
            if (len(keys) != 11 and len(key0) == 32):
                return "Error: 10 keys were not created"
            elif (len(keys) != 13 and len(key0) == 48):
                return "Error: 12 keys were not created"
            elif (len(keys) != 15 and len(key0) == 64):
                return "Error: 14 keys were not created"

            plaintext = plaintext_orig[block_counter:block_counter + 32]

            # CBC mode
            if (ecb == False and block_counter > 0):
                plaintext = xor(plaintext, hex2bin(cipherText), 128).rjust(32, '0')

            # Add Round Key
            ark = xor(plaintext, hex2bin(keys[0]), 128).rjust(32, '0')

            round_length = len(keys) - 1
            for key_counter in range(1, round_length):
                #print("Key (e): %d" % (key_counter))
                #print("CP5 (e): " + ark + '\n')

                # SubBytes
                sb = subBytes(ark)
                #print("Post SubByte")
                #print("CP4 (e): " + sb + '\n')

                # ShiftRows
                fourByfour = [[sb[0:2], sb[8:10],  sb[16:18], sb[24:26]],
                              [sb[2:4], sb[10:12], sb[18:20], sb[26:28]],
                              [sb[4:6], sb[12:14], sb[20:22], sb[28:30]],
                              [sb[6:8], sb[14:16], sb[22:24], sb[30:32]]]
                fourByfour = shiftRows(fourByfour)

                check = []
                for i in range(0, 4):
                    col2row = []
                    for j in range(0, 4):
                        col2row.append(fourByfour[j][i])
                    check.append(''.join(col2row))
                #print("Post shiftRows")
                #print("CP3 (e): " + ''.join(check) + '\n')

                # Mix Columns
                mix_cols = []
                for i in range(0, 4):
                    col = []
                    for j in range(0, 4):
                        col.append(fourByfour[j][i])
                    mix = mixCols(''.join(col))
                    mix_cols.append(mix)

                # re-order the matrix to 128 bits
                mixed = ''.join(mix_cols)
                # error checking
                if(len(mixed) != 32):
                    return "Error after mixing columns"
                #print("Post mixCols")
                #print("CP2 (e): " + mixed + '\n')
                # Add Round Key
                ark = xor(mixed, hex2bin(keys[key_counter]), 128).rjust(32, '0')
                #print("Post Add Round Key")
                #print("CP1 (e): " + ark + '\n')

            #print("CP2 (e): " + ark)
            # SubBytes
            sb = subBytes(ark)

            # Shift Rows
            fourByfour = [[sb[0:2], sb[8:10], sb[16:18], sb[24:26]],
                          [sb[2:4], sb[10:12], sb[18:20], sb[26:28]],
                          [sb[4:6], sb[12:14], sb[20:22], sb[28:30]],
                          [sb[6:8], sb[14:16], sb[22:24], sb[30:32]]]
            fourByfour = shiftRows(fourByfour)

            final = []
            for i in range(0, 4):
                col2row = []
                for j in range(0, 4):
                    col2row.append(fourByfour[j][i])
                final.append(''.join(col2row))

            checkVal = ''.join(final)
            #print("CP1 (e): " + checkVal)
            # Add Round Key
            cipherText = xor(checkVal, hex2bin(keys[len(keys) - 1]), len(plaintext) * 4).rjust(len(plaintext), '0')
            final_ciphertext.append(cipherText)
        # convert the ciphertext list into a ciphertext string
        ciphertext_string = ''
        for l in range(0, len(final_ciphertext)):
            ciphertext_string += final_ciphertext[l]
        return ciphertext_string

# Function: Decrypt ciphertext using AES
# Input: ciphertext (hex string), key0 (hex string)
# Output: plaintext (hex string)
def AES_decryption(ciphertext_string, key0, ebc = True):
    if not ciphertext_string:
        print("empty ciphertext")
    else:
        # check length of initial key
        if (len(key0) != 32 and len(key0) != 48 and len(key0) != 64):
            return "Error: initial key is not 128, 192, or 256 bits"

        # convert ciphertext string into list
        ciphertext_list = []
        for length_string in range(0, len(ciphertext_string) - 1, 32):
            ciphertext_list.append(ciphertext_string[length_string:length_string + 32])

        plaintext_list = []

        for cipher_length in range(len(ciphertext_list) - 1, -1, -1):
            keys = key_exp(key0, len(key0) * 4)

            if (len(keys) != 11 and len(key0) == 32):
                return "Error: 10 keys were not created"
            elif (len(keys) != 13 and len(key0) == 48):
                return "Error: 12 keys were not created"
            elif (len(keys) != 15 and len(key0) == 64):
                return "Error: 14 keys were not created"

            ciphertext = ciphertext_list[cipher_length]

            # Add Round Key
            ark = xor(ciphertext, hex2bin(keys[len(keys) - 1]), 128).rjust(32, '0')
            #print("CP1 (d): " + ark)
            # Inv Shift Rows
            fourByfour = [[ark[0:2], ark[8:10],  ark[16:18], ark[24:26]],
                          [ark[2:4], ark[10:12], ark[18:20], ark[26:28]],
                          [ark[4:6], ark[12:14], ark[20:22], ark[28:30]],
                          [ark[6:8], ark[14:16], ark[22:24], ark[30:32]]]
            inv_shift = invShiftRows(fourByfour)

            back_to_128 = []
            for i in range(0, 4):
                col2row = []
                for j in range(0, 4):
                    col2row.append(inv_shift[j][i])
                back_to_128.append(''.join(col2row))

            # Inv SubBytes
            start_loop = invSubBytes(''.join(back_to_128))

            #print("CP2 (d): " + start_loop)

            for key_counter in range(len(keys) - 2, 0, -1):
                #print("Key (d): %d" % (key_counter))

                #print("CP1 (d): " + start_loop + '\n')

                # Add Round Key
                ark = xor(start_loop, hex2bin(keys[key_counter]), 128).rjust(32, '0')
                #print("Post invert Add Round Key")
                #print("CP2 (d): " + ark + '\n')

                fourByfour = [[ark[0:2], ark[8:10], ark[16:18], ark[24:26]],
                              [ark[2:4], ark[10:12], ark[18:20], ark[26:28]],
                              [ark[4:6], ark[12:14], ark[20:22], ark[28:30]],
                              [ark[6:8], ark[14:16], ark[22:24], ark[30:32]]]
                # Inv Mix Columns
                mix_cols = []
                for i in range(0, 4):
                    col = []
                    for j in range(0, 4):
                        col.append(fourByfour[j][i])
                    mix = invMixCols(''.join(col))
                    mix_cols.append(mix)

                # re-order the matrix to 128 bits
                sb = ''.join(mix_cols)
                #print("Post invert MixCols")
                #print("CP3 (d): " + sb + '\n')

                if (len(sb) != 32):
                    return "Error after mixing columns"

                # Inv ShiftRows
                fourByfour = [[sb[0:2], sb[8:10], sb[16:18], sb[24:26]],
                              [sb[2:4], sb[10:12], sb[18:20], sb[26:28]],
                              [sb[4:6], sb[12:14], sb[20:22], sb[28:30]],
                              [sb[6:8], sb[14:16], sb[22:24], sb[30:32]]]
                inv_shift = invShiftRows(fourByfour)

                back_to_128 = []
                for i in range(0, 4):
                    col2row = []
                    for j in range(0, 4):
                        col2row.append(inv_shift[j][i])
                    back_to_128.append(''.join(col2row))
                #print("Post invert shift rows")
                #print("CP4 (d): " + ''.join(back_to_128) + '\n')

                # Inv SubBytes
                start_loop = invSubBytes(''.join(back_to_128))
                #print("Post invert sub bytes")
                #print("CP5 (d): " + start_loop + '\n')

            checkVal = ''.join(start_loop)
            # Final Add Round Key
            plainText = xor(checkVal, hex2bin(keys[0]), len(ciphertext) * 4).rjust(len(ciphertext), '0')

            if(ebc == False and cipher_length > 0):
                plainText = xor(plainText, hex2bin(ciphertext))

            plaintext_list.append(plainText)
        # convert plaintext list to string of plaintext
        string_plaintext = ''
        for k in range(len(plaintext_list) - 1, -1, -1):
            string_plaintext += plaintext_list[k]
        return string_plaintext
