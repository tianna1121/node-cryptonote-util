#include <cmath>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <string>
#include <algorithm>
#include "cryptonote_core/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "cryptonote_protocol/blobdatatype.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "common/base58.h"
#include "serialization/binary_utils.h"

#include <nan.h>

using namespace node;
using namespace v8;
using namespace cryptonote;

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

// Handle<Value> except(const char* msg) {
    // return ThrowException(Exception::Error(String::New(msg)));
// }

blobdata uint64be_to_blob(uint64_t num) {
    blobdata res = "        ";
    res[0] = num >> 56 & 0xff;
    res[1] = num >> 48 & 0xff;
    res[2] = num >> 40 & 0xff;
    res[3] = num >> 32 & 0xff;
    res[4] = num >> 24 & 0xff;
    res[5] = num >> 16 & 0xff;
    res[6] = num >> 8  & 0xff;
    res[7] = num       & 0xff;
    return res;
}


static bool fillExtra(cryptonote::block& block1, const cryptonote::block& block2) {
    cryptonote::tx_extra_merge_mining_tag mm_tag;
    mm_tag.depth = 0;
    if (!cryptonote::get_block_header_hash(block2, mm_tag.merkle_root))
        return false;

    block1.miner_tx.extra.clear();
    if (!cryptonote::append_mm_tag_to_extra(block1.miner_tx.extra, mm_tag))
        return false;

    return true;
}

static bool mergeBlocks(const cryptonote::block& block1, cryptonote::block& block2, const std::vector<crypto::hash>& branch2) {
    block2.timestamp = block1.timestamp;
    block2.parent_block.major_version = block1.major_version;
    block2.parent_block.minor_version = block1.minor_version;
    block2.parent_block.prev_id = block1.prev_id;
    block2.parent_block.nonce = block1.nonce;
    block2.parent_block.miner_tx = block1.miner_tx;
    block2.parent_block.number_of_transactions = block1.tx_hashes.size() + 1;
    block2.parent_block.miner_tx_branch.resize(crypto::tree_depth(block1.tx_hashes.size() + 1));
    std::vector<crypto::hash> transactionHashes;
    transactionHashes.push_back(cryptonote::get_transaction_hash(block1.miner_tx));
    std::copy(block1.tx_hashes.begin(), block1.tx_hashes.end(), std::back_inserter(transactionHashes));
    tree_branch(transactionHashes.data(), transactionHashes.size(), block2.parent_block.miner_tx_branch.data());
    block2.parent_block.blockchain_branch = branch2;
    return true;
}

static bool construct_parent_block(const cryptonote::block& b, cryptonote::block& parent_block) {
    if (b.major_version >= 3) {
        parent_block.minor_version = 1;
    }
    else {
        parent_block.minor_version = 0;
    }

    parent_block.major_version = 1;
    parent_block.timestamp = b.timestamp;
    parent_block.prev_id = b.prev_id;
    parent_block.nonce = b.parent_block.nonce;
    parent_block.miner_tx.version = CURRENT_TRANSACTION_VERSION;
    parent_block.miner_tx.unlock_time = 0;

    return fillExtra(parent_block, b);
}

// Handle<Value> convert_blob(const Arguments& args) {
//     HandleScope scope;

//     if (args.Length() < 1)
//         THROW_ERROR_EXCEPTION("You must provide one argument.");

//     Local<Object> target = args[0]->ToObject();

//     if (!Buffer::HasInstance(target))
//         THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

//     blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
//     blobdata output = "";

//     //convert
//     block b = AUTO_VAL_INIT(b);
//     if (!parse_and_validate_block_from_blob(input, b))
//         THROW_ERROR_EXCEPTION("Failed to parse block");

//     if (b.major_version < BLOCK_MAJOR_VERSION_2) {
//         if (!get_block_hashing_blob(b, output))
//             THROW_ERROR_EXCEPTION("Failed to create mining block");
//     } else {
//         block parent_block;
//         if (!construct_parent_block(b, parent_block))
//             THROW_ERROR_EXCEPTION("Failed to construct parent block");

//         if (!get_block_hashing_blob(parent_block, output))
//             THROW_ERROR_EXCEPTION("Failed to create mining block");
//     }

//     Buffer* buff = Buffer::New(output.data(), output.size());
//     return scope.Close(buff->handle_);
// }

NAN_METHOD(convert_blob) {
    if (info.Length() < 1)
        THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    //convert
    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b))
        THROW_ERROR_EXCEPTION("Failed to parse block");

    if (b.major_version < BLOCK_MAJOR_VERSION_2) {
        if (!get_block_hashing_blob(b, output))
            THROW_ERROR_EXCEPTION("Failed to create mining block");
    } else {
        block parent_block;
        if (!construct_parent_block(b, parent_block))
            THROW_ERROR_EXCEPTION("Failed to construct parent block");

        if (!get_block_hashing_blob(parent_block, output))
            THROW_ERROR_EXCEPTION("Failed to create mining block");
    }

    // Buffer* buff = Buffer::New(output.data(), output.size());
    // return scope.Close(buff->handle_);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}


// Handle<Value> get_block_id(const Arguments& args) {
//     HandleScope scope;

//     if (args.Length() < 1)
//         THROW_ERROR_EXCEPTION("You must provide one argument.");

//     Local<Object> target = args[0]->ToObject();

//     if (!Buffer::HasInstance(target))
//         THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

//     blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
//     blobdata output = "";

//     block b = AUTO_VAL_INIT(b);
//     if (!parse_and_validate_block_from_blob(input, b))
//         THROW_ERROR_EXCEPTION("Failed to parse block");

//     crypto::hash block_id;
//     if (!get_block_hash(b, block_id))
//         THROW_ERROR_EXCEPTION("Failed to calculate hash for block");

//     Buffer* buff = Buffer::New(reinterpret_cast<char*>(&block_id), sizeof(block_id));
//     return scope.Close(buff->handle_);
// }

NAN_METHOD(get_block_id) {
    if (info.Length() < 1)
        THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b))
        THROW_ERROR_EXCEPTION("Failed to parse block");

    crypto::hash block_id;
    if (!get_block_hash(b, block_id))
        THROW_ERROR_EXCEPTION("Failed to calculate hash for block");

    // Buffer* buff = Buffer::New(reinterpret_cast<char*>(&block_id), sizeof(block_id));
    // return scope.Close(buff->handle_);

    char* cstr = reinterpret_cast<char*>(&block_id);
    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(cstr, 32).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

// Handle<Value> construct_block_blob(const Arguments& args) {
//     HandleScope scope;

//     if (args.Length() < 2)
//         THROW_ERROR_EXCEPTION("You must provide two arguments.");

//     Local<Object> block_template_buf = args[0]->ToObject();
//     Local<Object> nonce_buf = args[1]->ToObject();

//     if (!Buffer::HasInstance(block_template_buf) || !Buffer::HasInstance(nonce_buf))
//         THROW_ERROR_EXCEPTION("Both arguments should be buffer objects.");

//     if (Buffer::Length(nonce_buf) != 4)
//         THROW_ERROR_EXCEPTION("Nonce buffer has invalid size.");

//     uint32_t nonce = *reinterpret_cast<uint32_t*>(Buffer::Data(nonce_buf));

//     blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
//     blobdata output = "";

//     block b = AUTO_VAL_INIT(b);
//     if (!parse_and_validate_block_from_blob(block_template_blob, b))
//         THROW_ERROR_EXCEPTION("Failed to parse block");

//     b.nonce = nonce;
//     if (b.major_version == BLOCK_MAJOR_VERSION_2) {
//         block parent_block;
//         b.parent_block.nonce = nonce;
//         if (!construct_parent_block(b, parent_block))
//             THROW_ERROR_EXCEPTION("Failed to construct parent block");

//         if (!mergeBlocks(parent_block, b, std::vector<crypto::hash>()))
//             THROW_ERROR_EXCEPTION("Failed to postprocess mining block");
//     }
//     if (b.major_version == BLOCK_MAJOR_VERSION_3) {
//         block parent_block;
//         b.parent_block.nonce = nonce;
//         if (!construct_parent_block(b, parent_block))
//             THROW_ERROR_EXCEPTION("Failed to construct parent block");

//         if (!mergeBlocks(parent_block, b, std::vector<crypto::hash>()))
//             THROW_ERROR_EXCEPTION("Failed to postprocess mining block");
//     }

//     if (!block_to_blob(b, output))
//         THROW_ERROR_EXCEPTION("Failed to convert block to blob");

//     Buffer* buff = Buffer::New(output.data(), output.size());
//     return scope.Close(buff->handle_);
// }

NAN_METHOD(construct_block_blob) {
    if (info.Length() < 2)
        THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> block_template_buf = info[0]->ToObject();
    Local<Object> nonce_buf = info[1]->ToObject();

    if (!Buffer::HasInstance(block_template_buf) || !Buffer::HasInstance(nonce_buf))
        THROW_ERROR_EXCEPTION("Both arguments should be buffer objects.");

    if (Buffer::Length(nonce_buf) != 4)
        THROW_ERROR_EXCEPTION("Nonce buffer has invalid size.");

    uint32_t nonce = *reinterpret_cast<uint32_t*>(Buffer::Data(nonce_buf));

    blobdata block_template_blob = std::string(Buffer::Data(block_template_buf), Buffer::Length(block_template_buf));
    blobdata output = "";

    block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(block_template_blob, b))
        THROW_ERROR_EXCEPTION("Failed to parse block");

    b.nonce = nonce;
    if (b.major_version == BLOCK_MAJOR_VERSION_2) {
        block parent_block;
        b.parent_block.nonce = nonce;
        if (!construct_parent_block(b, parent_block))
            THROW_ERROR_EXCEPTION("Failed to construct parent block");

        if (!mergeBlocks(parent_block, b, std::vector<crypto::hash>()))
            THROW_ERROR_EXCEPTION("Failed to postprocess mining block");
    }
    if (b.major_version == BLOCK_MAJOR_VERSION_3) {
        block parent_block;
        b.parent_block.nonce = nonce;
        if (!construct_parent_block(b, parent_block))
            THROW_ERROR_EXCEPTION("Failed to construct parent block");

        if (!mergeBlocks(parent_block, b, std::vector<crypto::hash>()))
            THROW_ERROR_EXCEPTION("Failed to postprocess mining block");
    }
    if (b.major_version == BLOCK_MAJOR_VERSION_4) {
        block parent_block;
        b.parent_block.nonce = nonce;
        if (!construct_parent_block(b, parent_block))
            THROW_ERROR_EXCEPTION("Failed to construct parent block");

        if (!mergeBlocks(parent_block, b, std::vector<crypto::hash>()))
            THROW_ERROR_EXCEPTION("Failed to postprocess mining block");
    }

    if (!block_to_blob(b, output))
        THROW_ERROR_EXCEPTION("Failed to convert block to blob");

    // Buffer* buff = Buffer::New(output.data(), output.size());
    // return scope.Close(buff->handle_);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

// Handle<Value> convert_blob_bb(const Arguments& args) {
//     HandleScope scope;

//     if (args.Length() < 1)
//         THROW_ERROR_EXCEPTION("You must provide one argument.");

//     Local<Object> target = args[0]->ToObject();

//     if (!Buffer::HasInstance(target))
//         THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

//     blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
//     blobdata output = "";

//     //convert
//     bb_block b = AUTO_VAL_INIT(b);
//     if (!parse_and_validate_block_from_blob(input, b)) {
//         THROW_ERROR_EXCEPTION("Failed to parse block");
//     }
//     output = get_block_hashing_blob(b);

//     Buffer* buff = Buffer::New(output.data(), output.size());
//     return scope.Close(buff->handle_);
// }

NAN_METHOD(convert_blob_bb) {
    if (info.Length() < 1)
        THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));
    blobdata output = "";

    //convert
    bb_block b = AUTO_VAL_INIT(b);
    if (!parse_and_validate_block_from_blob(input, b)) {
        THROW_ERROR_EXCEPTION("Failed to parse block");
    }
    output = get_block_hashing_blob(b);

    // Buffer* buff = Buffer::New(output.data(), output.size());
    // return scope.Close(buff->handle_);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output.data(), output.size()).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}

NAN_METHOD(address_decode) {
    if (info.Length() < 1)
        THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if (!Buffer::HasInstance(target))
        THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    blobdata input = std::string(Buffer::Data(target), Buffer::Length(target));

    blobdata data;
    uint64_t prefix;
    if (!tools::base58::decode_addr(input, prefix, data)){
        // return scope.Close(Undefined());
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    account_public_address adr;
    if (!::serialization::parse_binary(data, adr)) {
        // return scope.Close(Undefined());
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    if (!crypto::check_key(adr.m_spend_public_key) || !crypto::check_key(adr.m_view_public_key)) {
        // return scope.Close(Undefined());
        info.GetReturnValue().Set(Nan::Undefined());
        return;
    }

    // return scope.Close(Integer::New(static_cast<uint32_t>(prefix)));
    info.GetReturnValue().Set(Nan::New(static_cast<uint32_t>(prefix)));
}

NAN_METHOD(cn_slowhash_variant_nimp) {
    if (info.Length() < 2)
        THROW_ERROR_EXCEPTION("You must provide 2 arguments.");

    Local<Object> a_input = info[0]->ToObject();
    uint32_t a_variant = info[1]->Uint32Value();

    if (!Buffer::HasInstance(a_input))
        THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char* input = Buffer::Data(a_input);
    char output[32];
    uint32_t input_len = Buffer::Length(a_input);

    if (a_variant > 0 && input_len < 43) THROW_ERROR_EXCEPTION("Variants need more than 43 bytes input.");

    crypto::cn_slow_hash_variant(input, input_len, output, a_variant);

    v8::Local<Object> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(
        returnValue
    );
}


// void init(Handle<Object> exports) {
//     exports->Set(String::NewSymbol("construct_block_blob"), FunctionTemplate::New(construct_block_blob)->GetFunction());
//     exports->Set(String::NewSymbol("get_block_id"), FunctionTemplate::New(get_block_id)->GetFunction());
//     exports->Set(String::NewSymbol("convert_blob"), FunctionTemplate::New(convert_blob)->GetFunction());
//     exports->Set(String::NewSymbol("convert_blob_bb"), FunctionTemplate::New(convert_blob_bb)->GetFunction());
//     exports->Set(String::NewSymbol("address_decode"), FunctionTemplate::New(address_decode)->GetFunction());
// }

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("construct_block_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(construct_block_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("get_block_id").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(get_block_id)).ToLocalChecked());
    Nan::Set(target, Nan::New("convert_blob").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob)).ToLocalChecked());
    Nan::Set(target, Nan::New("convert_blob_bb").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(convert_blob_bb)).ToLocalChecked());
    Nan::Set(target, Nan::New("address_decode").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(address_decode)).ToLocalChecked());
    Nan::Set(target, Nan::New("cn_slowhash_variant").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cn_slowhash_variant_nimp)).ToLocalChecked());
}

NODE_MODULE(cryptonote, init)
