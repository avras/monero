#include "ringct/rctSigs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "../io.h"

struct lsagSig {
  rct::keyV ss;
  rct::key c;
  rct::key I;
};

lsagSig LSAG_Gen(const rct::key &message, const rct::keyV & pk, const rct::key & x, const unsigned int index, hw::device &hwdev) {
    lsagSig rv;
    size_t cols = pk.size();
    CHECK_AND_ASSERT_THROW_MES(cols >= 2, "Error! Why ring signature if cols = 1!");
    CHECK_AND_ASSERT_THROW_MES(index < cols, "Index out of range");

    size_t i = 0;
    rct::key c, c_old, L, R, Hi, aHP;
    sc_0(c_old.bytes);
    rct::geDsmp Ip;
    rct::key alpha;
    rct::key aG;

    rv.ss = rct::keyV(cols);
    rct::keyV toHash(4);
    toHash[0] = message;
    toHash[1] = pk[index];
    Hi = hashToPoint(pk[index]);
    hwdev.mlsag_prepare(Hi, x, alpha, aG, aHP, rv.I);
    toHash[2] = aG;
    toHash[3] = aHP;
    precomp(Ip.k, rv.I);

    hwdev.mlsag_hash(toHash, c_old);

    i = (index + 1) % cols;
    if (i == 0) {
        copy(rv.c, c_old);
    }
    while (i != index) {

        rv.ss[i] = rct::skGen();
        sc_0(c.bytes);
        addKeys2(L, rv.ss[i], c_old, pk[i]);
        hashToPoint(Hi, pk[i]);
        addKeys3(R, rv.ss[i], Hi, c_old, Ip.k);
        toHash[1] = pk[i];
        toHash[2] = L;
        toHash[3] = R;
        hwdev.mlsag_hash(toHash, c);
        copy(c_old, c);
        i = (i + 1) % cols;

        if (i == 0) {
            copy(rv.c, c_old);
        }
    }

    sc_mulsub(rv.ss[index].bytes, c.bytes, x.bytes, alpha.bytes);
    return rv;
}

bool LSAG_Ver(const rct::key &message, const rct::keyV & pk, const lsagSig & rv) {

    size_t cols = pk.size();
    CHECK_AND_ASSERT_MES(cols >= 2, false, "Error! Why ring signature if cols = 1!");
    CHECK_AND_ASSERT_MES(rv.ss.size() == cols, false, "Bad rv.ss size");

    for (size_t i = 0; i < rv.ss.size(); ++i)
        CHECK_AND_ASSERT_MES(sc_check(rv.ss[i].bytes) == 0, false, "Bad ss slot");
    CHECK_AND_ASSERT_MES(sc_check(rv.c.bytes) == 0, false, "Bad c");

    size_t i = 0;
    rct::key c,  L, R, Hi;
    rct::key c_old = copy(rv.c);
    rct::geDsmp Ip;
    precomp(Ip.k, rv.I);

    rct::keyV toHash(4);
    toHash[0] = message;
    i = 0;
    while (i < cols) {
        sc_0(c.bytes);
        addKeys2(L, rv.ss[i], c_old, pk[i]);
        hashToPoint(Hi, pk[i]);
        CHECK_AND_ASSERT_MES(!(Hi == rct::identity()), false, "Data hashed to point at infinity");
        addKeys3(R, rv.ss[i], Hi, c_old, Ip.k);
        toHash[1] = pk[i];
        toHash[2] = L;
        toHash[3] = R;
        c = hash_to_scalar(toHash);
        copy(c_old, c);
        i = (i + 1);
    }
    sc_sub(c.bytes, c_old.bytes, rv.c.bytes);
    return sc_isnonzero(c.bytes) == 0;
}

struct ringSig {
  rct::keyV ss;
  rct::key c;
};

ringSig RingSig_Gen(const rct::key &message, const rct::keyV & pk, const rct::key & x, const unsigned int index) {
    ringSig rv;
    size_t cols = pk.size();
    CHECK_AND_ASSERT_THROW_MES(cols >= 2, "Error! Why ring signature if cols = 1!");
    CHECK_AND_ASSERT_THROW_MES(index < cols, "Index out of range");

    size_t i = 0;
    rct::key c, c_old, L;
    sc_0(c_old.bytes);
    rct::key alpha;
    rct::key aG;

    rv.ss = rct::keyV(cols);
    rct::keyV toHash(cols+2);

    for (i = 0 ; i < cols ; i++)
    {
      toHash[i] = pk[i];
    }
    toHash[cols] = message;
    rct::skpkGen(alpha, aG);
    toHash[cols+1] = aG;

    c_old = rct::hash_to_scalar(toHash);

    i = (index + 1) % cols;
    if (i == 0) {
        copy(rv.c, c_old);
    }
    while (i != index) {

        rv.ss[i] = rct::skGen();
        sc_0(c.bytes);
        addKeys2(L, rv.ss[i], c_old, pk[i]);
        toHash[cols+1] = L;
        c = hash_to_scalar(toHash);
        copy(c_old, c);
        i = (i + 1) % cols;

        if (i == 0) {
            copy(rv.c, c_old);
        }
    }

    sc_mulsub(rv.ss[index].bytes, c.bytes, x.bytes, alpha.bytes);
    return rv;
}

bool RingSig_Ver(const rct::key &message, const rct::keyV & pk, const ringSig & rv) {
    size_t cols = pk.size();
    CHECK_AND_ASSERT_MES(cols >= 2, false, "Error! Why ring signature if cols = 1!");
    CHECK_AND_ASSERT_MES(rv.ss.size() == cols, false, "Bad rv.ss size");

    for (size_t i = 0; i < rv.ss.size(); ++i)
        CHECK_AND_ASSERT_MES(sc_check(rv.ss[i].bytes) == 0, false, "Bad ss slot");
    CHECK_AND_ASSERT_MES(sc_check(rv.c.bytes) == 0, false, "Bad c");

    size_t i = 0;
    rct::key c, L;
    rct::key c_old = copy(rv.c);

    rct::keyV toHash(cols+2);
    for (i = 0 ; i < cols ; i++)
    {
      toHash[i] = pk[i];
    }
    toHash[cols] = message;

    i = 0;
    while (i < cols) {
        sc_0(c.bytes);
        addKeys2(L, rv.ss[i], c_old, pk[i]);
        toHash[cols+1] = L;
        c = hash_to_scalar(toHash);
        copy(c_old, c);
        i = (i + 1);
    }
    sc_sub(c.bytes, c_old.bytes, rv.c.bytes);
    return sc_isnonzero(c.bytes) == 0;
}

