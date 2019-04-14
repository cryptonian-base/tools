#include <iostream>
#include <cstring>
#include <fstream>

#include "sha256.h"

#define BLOCKNUM        5

#define FILENAME_CHARARRAY  "chararray.inputs"

#define BUFSIZE 512
#define PACKETSIZE sizeof(MSG)

using namespace std;

typedef struct MSG
{
    int type;
    int priority;
    int sender;
    char message[BUFSIZE];
}MSG;

#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 uint8_t digest
#define MAXLEVEL 1 //log(target)

typedef struct Entry {
	uint8_t hash[SHA256_BLOCK_SIZE]; //32Byte
}Entry_t;

typedef struct _BlockSchema{
	uint64_t prevHash[4]; //0
	uint64_t hash[4]; //32
	uint64_t height; //64
	uint64_t timestamp; //72
	uint64_t nonce;	//80
	Entry_t interlink[MAXLEVEL]; //88
} BlockSchema; //88 + 32

void serialize(MSG* msgPacket, char *data);
void deserialize(char *data, MSG* msgPacket);
void printMsg(MSG* msgPacket);


void copyHash (uint64_t *src, uint64_t *dst) {
    for (int i = 0; i<4; i++) {
        dst[i] = src[i];
    }
}
void resetHash(uint64_t *dst) {
    for (int i = 0; i<4; i++) {
        dst[i] = 0;
    }
}


BlockSchema* gBlockList[BLOCKNUM];

BlockSchema* mineNewBlock(int height, BlockSchema* parent) {
    BlockSchema* newBlock = new BlockSchema;
    newBlock->height = height;
    newBlock->timestamp = 1000;
    newBlock->nonce = 999;
    if (height != 0 && parent != NULL) {
        // Setting prevHash
        copyHash(parent->hash, newBlock->prevHash);
    } else {
        resetHash(newBlock->prevHash);
    }

    for (int i=0; i<MAXLEVEL; i++) {
        Entry_t* entry = &(newBlock->interlink[i]);
        for (int j=0; j<SHA256_BLOCK_SIZE; j++){
            entry->hash[j] = 0;
        }
    }

    // calculate the current Hash..
    uint8_t prover_hash[SHA256_BLOCK_SIZE];         /* this is the hash of private preimage */

	SHA256_CTX ctx;
    sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t*)newBlock, sizeof(BlockSchema)); //[minzzii] len=120인경우 "No function definition for memset" 에러가 남 => sha256_finalize에서 해당함수 수정
	sha256_final(&ctx, prover_hash);

    copyHash((uint64_t*) prover_hash, newBlock->hash);

    // Add new Block into global list of blocks
    gBlockList[height] = newBlock;

    return newBlock;
}



void serialize(MSG* msgPacket, char *data)
{
    int *q = (int*)data;    
    *q = msgPacket->type;       q++;    
    *q = msgPacket->priority;   q++;    
    *q = msgPacket->sender;     q++;

    char *p = (char*)q;
    int i = 0;
    while (i < BUFSIZE)
    {
        *p = msgPacket->message[i];
        p++;
        i++;
    }
}
void serialize_entry(Entry_t* entry, char *data)
{
    uint8_t *q = (uint8_t*)data;
    for (int i=0; i < SHA256_BLOCK_SIZE;i++) {
        *q = entry->hash[i];
        q++;
    }

}
void serialize_block(BlockSchema* block, char *data)
{
    uint64_t *q = (uint64_t*)data;    

    for (int i = 0; i < 4; i++) {
        *q = block->prevHash[i];
        q++;
    }
    for (int i = 0; i < 4; i++) {
        *q = block->hash[i];
        q++;
    }
    *q = block->height;
    *q = block->timestamp;
    *q = block->nonce;
    
    Entry_t *p = (Entry_t*) q;
    int j = 0;
    while( j<MAXLEVEL) {
        serialize_entry(&(block->interlink[j]), (char*)p);
        p++;
        j++;
    }
}

void serializeBlockchain(char *data) {

    BlockSchema *pBlock = (BlockSchema*)data;
    for (int i=0; i < BLOCKNUM; i++) {
        serialize_block(gBlockList[i], (char*) pBlock);
        pBlock++;
    }
}

void writeSerializedInfo(char *data) {
    string filename = FILENAME_CHARARRAY;
    ofstream writeFile(filename.data());

    if(writeFile.is_open()) {
        for(int i=0; i<(BLOCKNUM * sizeof(BlockSchema)); i++){
            writeFile << (uint32_t)(uint8_t) data[i] << "\n";
        }
        writeFile.close();
    }
}

void deserialize(char *data, MSG* msgPacket)
{
    int *q = (int*)data;    
    msgPacket->type = *q;       q++;    
    msgPacket->priority = *q;   q++;    
    msgPacket->sender = *q;     q++;

    char *p = (char*)q;
    int i = 0;
    while (i < BUFSIZE)
    {
        msgPacket->message[i] = *p;
        p++;
        i++;
    }
}


void deserialize_entry(char *data, Entry_t* entry)
{
    uint8_t* q = (uint8_t*)data;
    int i = 0;
    while ( i < SHA256_BLOCK_SIZE) {
        entry->hash[i] = *q;
        i++;
        q++;
    }
}
void deserialize_block(char *data, BlockSchema* block)
{
    uint64_t *q = (uint64_t*)data;  

    for (int i = 0; i < 4; i++) {
        block->prevHash[i] = *q;
        q++;
    }

    for (int i = 0; i < 4; i++) {
        block->hash[i] = *q;
        q++;
    }
    block->height = *q;     q++;
    block->timestamp = *q;  q++;
    block->nonce = *q;      q++;
    
    Entry_t *p = (Entry_t*) q;
    int j =0;
    while ( j<MAXLEVEL ) {
        deserialize_entry((char*)p, &(block->interlink[j]));
        j++;
        p++;
    }
}
void printEntry(Entry_t* entry) {
    for (int i=0; i<SHA256_BLOCK_SIZE; i++) {
        cout << entry->hash[i] << " ";
    } 
    cout << endl;
}

void printBlock(BlockSchema* block)
{
    cout << "===== Block =====" << endl;
    cout << block->prevHash[0] << " " << block->prevHash[1] << " " << block->prevHash[2] << " " << block->prevHash[3] << " "  << endl;
    cout << block->hash[0] << " " << block->hash[1] << " " << block->hash[2] << " " << block->hash[3] << " "  << endl;
    cout << block->height << endl;
    cout << block->timestamp << endl;
    cout << block->nonce << endl;

    for ( int i=0; i<MAXLEVEL; i++) {
        printEntry(&(block->interlink[i]));
    }
}

void printBlockchain()
{
    for(int i =0; i<BLOCKNUM; i++) {
        printBlock(gBlockList[i]);
    }
}

void printMsg(MSG* msgPacket)
{
    cout << msgPacket->type << endl;
    cout << msgPacket->priority << endl;
    cout << msgPacket->sender << endl;
    cout << msgPacket->message << endl;
}



int main()
{
#if 0
    MSG* newMsg = new MSG;
    newMsg->type = 1;
    newMsg->priority = 9;
    newMsg->sender = 2;
    strcpy(newMsg->message, "hello from server\0");
    printMsg(newMsg);

    char data[PACKETSIZE];

    serialize(newMsg, data);

    MSG* temp = new MSG;
    deserialize(data, temp);
    printMsg(temp);
#endif 
//===============//
    cout << "== Generating Blocks... ==" << endl;

    BlockSchema *genesisBlock = mineNewBlock(0, NULL);
    for(int i=1; i<BLOCKNUM; i++) {
        BlockSchema *block = mineNewBlock(i, gBlockList[i-1]);
    }
    printBlockchain();
    cout << "== Serializing... ==" << endl;

    char data[sizeof(BlockSchema) * BLOCKNUM];
    serializeBlockchain(data);

    //Write data into a File
    writeSerializedInfo(data);

    cout << "== Deserializing... ==" << endl;

    // deserialize
    BlockSchema* curBlock = (BlockSchema*)data;
    for (int i=0; i<BLOCKNUM; i++) {

        BlockSchema* temp = new BlockSchema;
        deserialize_block((char*)curBlock, temp);
        printBlock(temp);
        curBlock++;
    }

    return 0;
}


//=============================//
/**
 * SHA256 code from https://github.com/cnasikas/data-processing/tree/master/zkp/app/queries/sha256
**/
void sha256_transform(SHA256_CTX *ctx, uint8_t *data) {
	uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
	for ( ; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, uint8_t *data, uint32_t len) {
	uint32_t i;
	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, uint8_t *hash) {
	uint32_t i;
	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56) {
            ctx->data[i++] = 0x00;
        }
	} else {
		ctx->data[i++] = 0x80;
		while (i < 64) {
            ctx->data[i++] = 0x00;
        }
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}