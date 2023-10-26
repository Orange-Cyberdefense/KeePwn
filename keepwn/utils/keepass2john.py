#!/usr/bin/python3

import os
import struct
from binascii import hexlify
from keepwn.utils.logging import print_error

def process_1x_database(data, databaseName, maxInlineSize=1024):
    index = 8
    algorithm = None

    enc_flag = struct.unpack("<L", data[index:index+4])[0]
    index += 4
    if (enc_flag & 2 == 2):
        # AES
        algorithm = 0
    elif (enc_flag & 8):
        # Twofish
        algorithm = 1
    else:
        print_error("Unsupported file encryption!")
        exit(0)

    # TODO: keyfile processing

    # TODO: database version checking
    version = hexlify(data[index:index+4]).decode('utf-8')
    index += 4

    finalRandomseed = hexlify(data[index:index+16])
    index += 16

    encIV = hexlify(data[index:index+16]).decode('utf-8')
    index += 16

    numGroups = struct.unpack("<L", data[index:index+4])[0]
    index += 4
    numEntries = struct.unpack("<L", data[index:index+4])[0]
    index += 4

    contentsHash = hexlify(data[index:index+32]).decode('utf-8')
    index += 32

    transfRandomseed = hexlify(data[index:index+32]).decode('utf-8')
    index += 32

    keyTransfRounds = struct.unpack("<L", data[index:index+4])[0]

    filesize = len(data)
    datasize = filesize - 124

    if (filesize + datasize) < maxInlineSize:
        dataBuffer = hexlify(data[124:]).decode('utf-8')
        end = "*1*%ld*%s" % (datasize, hexlify(dataBuffer))
    else:
        end = "0*%s" % (databaseName)

    return "%s:$keepass$*1*%s*%s*%s*%s*%s*%s*%s" % (databaseName, keyTransfRounds, algorithm, finalRandomseed, transfRandomseed, encIV, contentsHash, end)

def process_2x_database(data, databaseName):

    index = 12
    endReached = False

    while not endReached:

        btFieldID = struct.unpack("B", data[index:index+1])[0]
        index += 1
        uSize = struct.unpack("H", data[index:index+2])[0]
        index += 2

        if btFieldID == 0:
            endReached = True

        if btFieldID == 4:
            masterSeed = hexlify(data[index:index+uSize]).decode('utf-8')

        if btFieldID == 5:
            transformSeed = hexlify(data[index:index+uSize]).decode('utf-8')

        if btFieldID == 6:
            transformRounds = struct.unpack("H", data[index:index+2])[0]

        if btFieldID == 7:
            initializationVectors = hexlify(data[index:index+uSize]).decode('utf-8')

        if btFieldID == 9:
            expectedStartBytes = hexlify(data[index:index+uSize]).decode('utf-8')

        index += uSize

    dataStartOffset = index
    firstEncryptedBytes = hexlify(data[index:index+32]).decode('utf-8')

    return "%s:$keepass$*2*%s*%s*%s*%s*%s*%s*%s" % (databaseName, transformRounds, dataStartOffset, masterSeed, transformSeed, initializationVectors, expectedStartBytes, firstEncryptedBytes)

def process_database(filename):

    f = open(filename, 'rb')
    data = f.read()
    f.close()

    base = os.path.basename(filename)
    databaseName = os.path.splitext(base)[0]

    fileSignature = hexlify(data[0:8])

    if fileSignature == b'03d9a29a67fb4bb5':
        # "2.X"
        hash = process_2x_database(data, databaseName)

    elif fileSignature == b'03d9a29a66fb4bb5':
        # "2.X pre release"
        hash = process_2x_database(data, databaseName)

    elif fileSignature == b'03d9a29a65fb4bb5':
        # "1.X"
        hash = process_1x_database(data, databaseName)
    else:
        print_error("ERROR: KeePass signature unrecognized")

    return hash