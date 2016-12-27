#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mss.h"


enum TREEHASH_STATE {
    TREEHASH_NEW = 0x20,
    TREEHASH_RUNNING = 0x40,
    TREEHASH_FINISHED = 0x80
};

#define TREEHASH_MASK   0x1F
#define TREEHASH_HEIGHT_INFINITY 0x7F

#if defined(DEBUG) || defined(MSS_SELFTEST)

#include <assert.h>

char dbg_seed_initialized = 0;
unsigned char dbg_seed[LEN_BYTES(MSS_SEC_LVL)];

unsigned char _node_valid_index(const unsigned char height, const unsigned short pos);
unsigned char _node_valid(const struct mss_node *node);
unsigned char _node_equal(const struct mss_node *node1, const struct mss_node *node2);
unsigned char _is_left_node(const struct mss_node *node);
unsigned char _is_right_node(const struct mss_node *node);
unsigned char _node_brothers(const struct mss_node *left_node, const struct mss_node *right_node);
unsigned char _count_trailing_zeros(const unsigned short v);

#ifdef DEBUG
#include "util.h"

void mss_node_print(const struct mss_node node);
void print_stack(const struct mss_node stack[MSS_KEEP_SIZE], const unsigned short top);
void print_stack_push(const struct mss_node stack[MSS_KEEP_SIZE], const unsigned short top, const struct mss_node node, const unsigned char pre_condition);
void print_stack_pop(const struct mss_node stack[MSS_KEEP_SIZE], const unsigned short top, const unsigned char pre_condition);
void print_auth(const struct mss_state *state);
void print_treehash(const struct mss_state *state);
void get_auth_index(unsigned short s, unsigned short auth_index[MSS_HEIGHT]); // Return the index of the authentication path for s-th leaf
void print_auth_index(unsigned short auth_index[MSS_HEIGHT - 1]);
void print_retain(const struct mss_state *state);

#endif

#endif

void _create_leaf(mmo_t *hash1, mmo_t *hash2, struct mss_node *node, const unsigned short leaf_index, const unsigned char seed[LEN_BYTES(MSS_SEC_LVL)]) {
    /********* Arrange *********/
    unsigned char sk[LEN_BYTES(MSS_SEC_LVL)];

#if defined(DEBUG) || defined(MSS_SELFTEST)
    // seed must always be the same
    if (!dbg_seed_initialized) {
        dbg_seed_initialized = 1;
        memmove(dbg_seed, seed, LEN_BYTES(MSS_SEC_LVL));
    } else {
        assert(memcmp(dbg_seed, seed, LEN_BYTES(MSS_SEC_LVL)) == 0);
    }
    // leaf_index must be between 0 and 2^MSS_HEIGHT-1
    assert(_node_valid_index(0, leaf_index));

    // sk has to be properly allocated
    assert(sizeof (sk) == LEN_BYTES(MSS_SEC_LVL) * sizeof (unsigned char));
#ifdef DEBUG
    printf("\n--Leaf %d. \n", leaf_index);
#endif 
#endif
    /********* Act *********/
    prg16(leaf_index, seed, sk); // sk := prg(seed,leaf_index)

    // Compute and store v in node->value
    winternitz_keygen(sk, hash1, hash2, node->value);
    // leaf = Hash(v)
    MMO_hash16(hash1, node->value, node->value);
    node->height = 0;
    node->index = leaf_index;

    /********* Assert *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(_node_valid(node));
    assert(node->height == 0);
    assert(node->index == leaf_index);
#endif
}

void _stack_push(struct mss_node stack[MSS_KEEP_SIZE], unsigned short *index, struct mss_node *node) {
    /********* Arrange *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(*index >= 0);
    assert(_node_valid(node));
    const unsigned short prior_index = *index;
#ifdef DEBUG
    print_stack_push(stack, *index, *node, 1);
#endif
#endif
    /********* Act *********/
    stack[*index] = *node;
    *index = *index + 1;
    /********* Assert *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(*index == prior_index + 1);
#ifdef DEBUG
    print_stack_push(stack, *index, *node, 0);
#endif
#endif
}

void _stack_pop(struct mss_node stack[MSS_KEEP_SIZE], unsigned short *index, struct mss_node *node) {
    /********* Arrange *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(*index > 0);
    const unsigned short prior_index = *index;
#ifdef DEBUG
    print_stack_pop(stack, *index, 1);
#endif
#endif
    /********* Act *********/
    *node = stack[--*index];
    /********* Assert *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(_node_valid(node));
    assert(*index == prior_index - 1);
#ifdef DEBUG
    print_stack_pop(stack, *index, 0);
#endif
#endif
}

void _get_parent(mmo_t *hash, const struct mss_node *left_child, const struct mss_node *right_child, struct mss_node *parent) {
    /********* Arrange *********/

#if defined(DEBUG) || defined(MSS_SELFTEST)
    unsigned char parent_height = left_child->height + 1;
    unsigned short parent_index = left_child->index / 2;
    assert(_node_valid(left_child));
    assert(_node_valid(right_child));
    // left_child and right_child must have the same height and be below the root
    assert(left_child->height < MSS_HEIGHT);
    assert(right_child->height < MSS_HEIGHT);
    assert(left_child->height == right_child->height);
    // left_child and right_child must be brothers
    // left_child->index must be even and right_child->index must be odd
    assert(_is_left_node(left_child));
    assert(_is_right_node(right_child));
    assert(right_child->index == left_child->index + 1);
#ifdef DEBUG
    printf("----- _get_parent -----\n\n");
    printf("Left Child\n");
    mss_node_print(*left_child);
    printf("Right Child\n");
    mss_node_print(*right_child);
    //getchar();
#endif
#endif
    /********* Act *********/
    MMO_hash32(hash, left_child->value, right_child->value, parent->value);

    parent->height = left_child->height + 1;
    parent->index = (left_child->index >> 1);
    /********* Assert *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(_node_valid(parent));
    // parent must be one height above childrem
    assert(parent->height == parent_height);
    // parent must have index equal the half of the childrem
    assert(parent->index == parent_index);
#ifdef DEBUG
    printf("Parent\n");
    mss_node_print(*parent);
    printf("-----------------------\n\n");
#endif
#endif
}

void init_state(struct mss_state *state) {
    /********* Arrange *********/
    /********* Act *********/
    state->stack_index = 0;

    memset(state->treehash_state, TREEHASH_FINISHED, MSS_TREEHASH_SIZE);
    memset(state->retain_index, 0, (MSS_K - 1) * sizeof (unsigned short));
    /********* Assert *********/
    //TODO
}

void _treehash_set_tailheight(struct mss_state *state, unsigned char h, unsigned char height) {
    /********* Arrange *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(h < MSS_TREEHASH_SIZE);
#endif
    /********* Act *********/
    state->treehash_state[h] &= 0xE0; // clear previous height
    state->treehash_state[h] |= (TREEHASH_MASK & height); // set new height
    /********* Assert *********/
}

unsigned char _treehash_get_tailheight(struct mss_state *state, unsigned char h) {
    /********* Arrange *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(h < MSS_TREEHASH_SIZE);
#endif
    /********* Act *********/
    return (TREEHASH_MASK & state->treehash_state[h]);
}

void _treehash_state(struct mss_state *state, unsigned char h, enum TREEHASH_STATE th_state) {
    /********* Arrange *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(h >= 0 && h < MSS_TREEHASH_SIZE);
#endif
    /********* Act *********/
    state->treehash_state[h] = th_state; // set state
    /********* Assert *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(_treehash_get_tailheight(state, h) == 0);
#endif
}

void _treehash_initialize(struct mss_state *state, unsigned char h, unsigned short s) {
    /********* Arrange *********/
    //TODO
    /********* Act *********/
    state->treehash_seed[h] = s;
    _treehash_state(state, h, TREEHASH_NEW);
    /********* Assert *********/
    //TODO
}

unsigned char _treehash_height(struct mss_state *state, unsigned char h) {
    /********* Arrange *********/
    unsigned char height = 0;
    //TODO
    /********* Act *********/
    switch (state->treehash_state[h] & ~TREEHASH_MASK) {
        case TREEHASH_NEW:
            height = h;
            break;
        case TREEHASH_RUNNING:
            if ((state->treehash_state[h] & TREEHASH_MASK) == h)
                height = TREEHASH_HEIGHT_INFINITY;
            else
                height = (state->treehash_state[h] & TREEHASH_MASK);
            break;
        case TREEHASH_FINISHED:
            height = TREEHASH_HEIGHT_INFINITY;
            break;
    }
    /********* Assert *********/
    //TODO
    return height;
}

void _treehash_update(mmo_t *hash1, mmo_t *hash2, struct mss_state *state, const unsigned char h, struct mss_node *node1, struct mss_node *node2, unsigned char seed[LEN_BYTES(MSS_SEC_LVL)]) {
    /********* Arrange *********/
    /********* Act *********/
    if (h < MSS_TREEHASH_SIZE - 1 && (state->treehash_seed[h] >= 11 * (1 << h)) && (((state->treehash_seed[h] - 11 * (1 << h)) % (1 << (2 + h))) == 0)) {
        node1->height = 0;
        node1->index = state->treehash_seed[h];
        memcpy(node1->value, state->store[h].value, NODE_VALUE_SIZE);
#ifdef DEBUG
        printf("Treehash %d recovered node %d \n", h, state->treehash_seed[h]);
#endif
    } else {
#ifdef DEBUG
        printf("Calc leaf in treehash%d: %d \n", h, state->treehash_seed[h]);
#endif
        _create_leaf(hash1, hash2, node1, state->treehash_seed[h], seed);
    }

    if (h > 0 && (state->treehash_seed[h] >= 11 * (1 << (h - 1))) && ((state->treehash_seed[h] - 11 * (1 << (h - 1))) % (1 << (h + 1)) == 0)) {
        state->store[h - 1].height = 0;
        state->store[h - 1].index = state->treehash_seed[h];
        memcpy(state->store[h - 1].value, node1->value, NODE_VALUE_SIZE);
#ifdef DEBUG
        printf("Treehash %d stored node %d \n", h, state->treehash_seed[h]);
#endif
    }

    state->treehash_seed[h]++;
    _treehash_set_tailheight(state, h, 0);

    while (state->stack_index > 0 && _treehash_get_tailheight(state, h) == state->stack[state->stack_index - 1].height && (_treehash_get_tailheight(state, h) + 1) < h) {
        _stack_pop(state->stack, &state->stack_index, node2);
        _get_parent(hash1, node2, node1, node1);
        _treehash_set_tailheight(state, h, _treehash_get_tailheight(state, h) + 1);
    }

    if (_treehash_get_tailheight(state, h) + 1 < h) {
        _stack_push(state->stack, &state->stack_index, node1);
        _treehash_state(state, h, TREEHASH_RUNNING);
    } else {
        if ((state->treehash_state[h] & TREEHASH_RUNNING) && (node1->index & 1)) { // if treehash *is used*
            *node2 = state->treehash[h];
            _get_parent(hash1, node2, node1, node1);
            _treehash_set_tailheight(state, h, _treehash_get_tailheight(state, h) + 1);
        }
        state->treehash[h] = *node1;
        if (node1->height == h) {
            _treehash_state(state, h, TREEHASH_FINISHED);
        } else {
            _treehash_state(state, h, TREEHASH_RUNNING);
        }
    }
    /********* Assert *********/
}

void _retain_push(struct mss_state *state, struct mss_node *node) {
    /********* Arrange *********/
    unsigned short index = (1 << (MSS_HEIGHT - node->height - 1)) - (MSS_HEIGHT - node->height - 1) - 1 + (node->index >> 1) - 1;
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(_node_valid(node));
    assert(state->retain_index[node->height - (MSS_HEIGHT - MSS_K)] == 0);
#endif
    /********* Act *********/
    state->retain[index] = *node;
    /********* Assert *********/
}

void _retain_pop(struct mss_state *state, struct mss_node *node, unsigned short h) {
    /********* Arrange *********/
    unsigned char hbar = (MSS_HEIGHT - h - 1);
    unsigned short index = (1 << hbar) - hbar - 1 + state->retain_index[h - (MSS_HEIGHT - MSS_K)];
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(h <= MSS_HEIGHT - 2);
    assert(h >= MSS_HEIGHT - MSS_K);
    assert(state->retain_index[h - (MSS_HEIGHT - MSS_K)] >= 0);
    assert(state->retain_index[h - (MSS_HEIGHT - MSS_K)] < (1 << hbar) - 1);
    assert(index >= 0);
    assert(index < MSS_RETAIN_SIZE);
#endif
    /********* Act *********/
    *node = state->retain[index];
    state->retain_index[h - (MSS_HEIGHT - MSS_K)]++;
    /********* Assert *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(_node_valid(node));
    assert(node->height == h);
#endif
}

void _init_state(struct mss_state *state, struct mss_node *node) {
    if (node->index == 1 && node->height < MSS_HEIGHT) {
        /********* Arrange *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
        assert(_node_valid(node));
        assert(node->index == 1);
        assert(node->height < MSS_HEIGHT);
#endif
        /********* Act *********/
        state->auth[node->height] = *node;
    }
    if (node->index == 3 && node->height < MSS_HEIGHT - MSS_K) {
        /********* Arrange *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
        assert(_node_valid(node));
        assert(node->index == 3);
        assert(node->height < MSS_HEIGHT - MSS_K);
#endif
        /********* Act *********/
        state->treehash[node->height] = *node;
        _treehash_initialize(state, node->height, node->index);
        _treehash_state(state, node->height, TREEHASH_FINISHED); // state is finished since it has already computed the respective treehash node
    }
    if (node->index >= 3 && ((node->index & 1) == 1) && node->height >= MSS_HEIGHT - MSS_K) {
        /********* Arrange *********/
#if defined(DEBUG) || defined(MSS_SELFTEST)
        assert(_node_valid(node));
        assert((node->height < MSS_HEIGHT - 1) && (node->height >= MSS_HEIGHT - MSS_K));
        assert(node->index >= 3 && ((node->index & 1) == 1));
#endif
        /********* Act *********/
        _retain_push(state, node);
    }
    /********* Assert *********/
}

unsigned char _count_trailing_zeros(const unsigned short v) {
    unsigned short c;
    unsigned char tz = 0;

    c = v;
    /* shift to count trailing zeros */
    while (!(c & 0x0001)) {
        c >>= 1;
        tz++;
    }
    return tz;
}

void mss_keygen_core(mmo_t *hash1, mmo_t *hash2, const unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], struct mss_node *node1, struct mss_node *node2, struct mss_state *state, unsigned char pkey[NODE_VALUE_SIZE]) {
    /********* Arrange *********/
    unsigned short i, index = 0;
    unsigned long pos;
    /********* Act *********/
    init_state(state);

    for (pos = 0; pos < ((unsigned long) 1 << MSS_HEIGHT); pos++) {

        _create_leaf(hash1, hash2, node1, pos, seed); //node1.height := 0
#if defined(DEBUG)
        mss_node_print(*node1);
#endif
        _init_state(state, node1);
        while (node1->height < (pos == 65535 ? 16 : _count_trailing_zeros(pos + 1))) { // Condition from algorithm 4.2 in Busold's thesis, adapted for unsigned short variables)
            _stack_pop(state->keep, &index, node2);
            _get_parent(hash1, node2, node1, node1);
#if defined(DEBUG)
            mss_node_print(*node1);
#endif
            _init_state(state, node1);
        }
        if (index < MSS_HEIGHT)
            _stack_push(state->keep, &index, node1);
    }

#if defined(DEBUG)
    print_auth(state);
    print_treehash(state);
    print_retain(state);
#endif
    for (i = 0; i < NODE_VALUE_SIZE; i++)
        pkey[i] = node1->value[i];
    /********* Assert *********/
}

void _nextAuth(struct mss_state *state, struct mss_node *current_leaf, unsigned char seed[LEN_BYTES(MSS_SEC_LVL)], mmo_t *hash1, mmo_t *hash2, struct mss_node *node1, struct mss_node *node2, const unsigned short s) {
    /********* Arrange *********/
    unsigned char tau = MSS_HEIGHT - 1;
    short min, h, i, j, k;
    /********* Act *********/
    while ((s + 1) % (1 << tau) != 0)
        tau--;

#if defined(DEBUG)
    printf("NextAuth: s = %d, tau = %d, nextleaf = %d\n", s, tau, s + 1);
#endif

    if (tau < MSS_HEIGHT - 1 && (((s >> (tau + 1)) & 1) == 0))
        state->keep[tau] = state->auth[tau];

    if (tau == 0) { // next leaf is a right node		
        state->auth[0] = *current_leaf; // Leaf was already computed because our nonce
    } else { // next leaf is a left node
        _get_parent(hash1, &state->auth[tau - 1], &state->keep[tau - 1], &state->auth[tau]);
        min = (tau - 1 < MSS_HEIGHT - MSS_K - 1) ? tau - 1 : MSS_HEIGHT - MSS_K - 1;
        for (h = 0; h <= min; h++) {

            //Do Treehash_h.pop()
            state->auth[h] = state->treehash[h];

            if (((unsigned long) s + 1 + 3 * (1 << h)) < ((unsigned long) 1 << MSS_HEIGHT))
                _treehash_initialize(state, h, s + 1 + 3 * (1 << h));
            else
                _treehash_state(state, h, TREEHASH_FINISHED);
        }
        h = MSS_HEIGHT - MSS_K;
        while (h < tau) {
            _retain_pop(state, &state->auth[h], h);
            h = h + 1;
        }
    }
    // UPDATE
    for (i = 0; i < (MSS_HEIGHT - MSS_K) / 2; i++) {
        min = TREEHASH_HEIGHT_INFINITY;
        k = MSS_HEIGHT - MSS_K - 1;
        for (j = MSS_HEIGHT - MSS_K - 1; j >= 0; j--) {
            if (_treehash_height(state, j) <= min) {
                min = state->treehash[j].height;
                k = j;
            }
        }
        if (!(state->treehash_state[k] & TREEHASH_FINISHED)) {
            _treehash_update(hash1, hash2, state, k, node1, node2, seed);
        }
    }
    /********* Assert *********/
}

void _get_pkey(mmo_t *hash, const struct mss_node auth[MSS_HEIGHT], struct mss_node *node, unsigned char *pkey) {
    /********* Arrange *********/
    unsigned char i, h;
    /********* Act *********/
    for (h = 0; h < MSS_HEIGHT; h++) {

#if defined(DEBUG) || defined(MSS_SELFTEST)
        assert(_node_valid(node));
        assert(_node_valid(&auth[h]));
        assert(auth[h].height == h);
        assert(auth[h].height == node->height);
#endif
        if (auth[h].index >= node->index) {
#if defined(DEBUG) || defined(MSS_SELFTEST)
            assert(_node_brothers(node, &auth[h]));
#endif
            _get_parent(hash, node, &auth[h], node);
        } else {
#if defined(DEBUG) || defined(MSS_SELFTEST)
            assert(_node_brothers(&auth[h], node));
#endif
            _get_parent(hash, &auth[h], node, node);
        }
    }
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(_node_valid(node));
    assert(node->height == MSS_HEIGHT);
    assert(node->index == 0);
#endif
    for (i = 0; i < NODE_VALUE_SIZE; i++)
        pkey[i] = node->value[i];
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert(memcmp(pkey, node->value, NODE_VALUE_SIZE) == 0);
#endif
}

/**
 * seed	 The initial seed for generating the private keys
 * v	 The leaf_index-th winternitz public key used as a nonce for the hash H(Y,v,M)
 *
 */

void mss_sign_core(struct mss_state *state, unsigned char *seed, struct mss_node *leaf, const char *data, unsigned short data_len,
        mmo_t *hash1, mmo_t *hash2, unsigned char *h, unsigned short leaf_index, struct mss_node *node1, struct mss_node *node2,
        unsigned char *sig, struct mss_node authpath[MSS_HEIGHT], const unsigned char *Y) {
    /********* Arrange *********/
    unsigned char i;
    mmo_t hash_mss;
    unsigned char sk[LEN_BYTES(MSS_SEC_LVL)];
#if defined(DEBUG) || defined(MSS_SELFTEST)
    assert((leaf_index >= 0) && (leaf_index < (1 << MSS_HEIGHT)));
#endif
    /********* Act *********/

    MMO_init(&hash_mss);
    // Feed the hash to be signed with Y, i.e. H(Y,...)
    MMO_update(&hash_mss, Y, 16);

    prg16(leaf_index, seed, sk);
    if (leaf_index % 2 == 0) { // leaf is a left child
#ifdef DEBUG
        printf("Calc leaf in sign: %d \n", leaf_index);
#endif
        // Compute and store v in leaf->value
        winternitz_keygen(sk, hash1, hash2, leaf->value);

        // Feed the hash to be signed with v, i.e. H(Y,v,...)
        MMO_update(&hash_mss, leaf->value, NODE_VALUE_SIZE);

        // leaf[leaf_index]->value = Hash(v)
        MMO_hash16(hash1, leaf->value, leaf->value);

    } else { // leaf is a right child and it is already available in the authentication path
        memcpy(leaf->value, authpath[0].value, NODE_VALUE_SIZE);
        // Feed the hash to be signed with v, i.e. H(Y,v,...)
        MMO_update(&hash_mss, leaf->value, NODE_VALUE_SIZE);
    }
    leaf->height = 0;
    leaf->index = leaf_index;

    // Feed the hash to be signed with data H(Y,v,data)
    MMO_update(&hash_mss, (const unsigned char *) data, 16);
    MMO_final(&hash_mss, h);

    winternitz_sign(sk, hash1, h, sig);

    for (i = 0; i < MSS_HEIGHT; i++) {
        authpath[i].height = state->auth[i].height;
        authpath[i].index = state->auth[i].index;
        memcpy(authpath[i].value, state->auth[i].value, NODE_VALUE_SIZE);
    }

    if (leaf_index <= ((unsigned long) 1 << MSS_HEIGHT) - 2)
        _nextAuth(state, leaf, seed, hash1, hash2, node1, node2, leaf_index);
    /********* Assert *********/
}

/**
 * s	 The leaf_index-th Winternitz private key
 * v	 The leaf_index-th Winternitz public key used as a nonce for the hash H(v,M)
 *
 */

unsigned char mss_verify_core(struct mss_node authpath[MSS_HEIGHT], const char *data, unsigned short data_len, mmo_t *hash1, mmo_t *hash2, unsigned char *h, unsigned short leaf_index, const unsigned char *sig, unsigned char *x, struct mss_node *currentLeaf, const unsigned char *Y) {
    /********* Arrange *********/
    /********* Act *********/
    mmo_t hash_mss;
    MMO_init(&hash_mss);
    // Feed the hash to be signed with Y, i.e. H(Y,...)
    MMO_update(&hash_mss, Y, 16);

    // compute v and put it in x
    winternitz_verify(x, hash1, hash2, h, sig, x);

    // Feed the hash to be signed with v, i.e. H(Y,v,...)
    MMO_update(&hash_mss, x, NODE_VALUE_SIZE);
    // Feed the hash to be signed with data H(Y,v,data)
    MMO_update(&hash_mss, (const unsigned char *) data, data_len);
    MMO_final(&hash_mss, h);

    // leaf = Hash(v)
    MMO_hash16(hash1, x, x);

    _get_pkey(hash1, authpath, currentLeaf, x);

    if (memcmp(currentLeaf->value, Y, NODE_VALUE_SIZE) == 0) {
#ifdef DEBUG
        printf("Assinatura eh valida para folha %d\n", leaf_index);
#endif // DEBUG
        return MSS_OK;
    }
    /********* Assert *********/

    return MSS_ERROR;
}

#ifdef SERIALIZATION

unsigned char *mss_keygen(const unsigned char seed[LEN_BYTES(MSS_SEC_LVL)]) {

    unsigned short i;
    unsigned char *keys = malloc(MSS_SKEY_SIZE + MSS_PKEY_SIZE);
    unsigned char pkey[MSS_PKEY_SIZE];
    struct mss_node node[2];
    struct mss_state state;
    mmo_t hash1, hash2;

#ifdef MSS_SELFTEST
    // Arrange
    //assert(sizeof(seed) == LEN_BYTES(MSS_SEC_LVL));
    // TODO: test node, state, hash_mmo and hadh_dm
#endif
    // Act

    /* Initialization of Davies-Meyer hash */
    //DM_init(&hash_dm);

    /* Initialization of Winternitz-MMO OTS */
    //MMO_init(&hash_mmo);

    mss_keygen_core(&hash1, &hash2, seed, &node[0], &node[1], &state, pkey);
    serialize_mss_skey(state, 0, seed, keys);

    for (i = 0; i < MSS_PKEY_SIZE; i++)
        keys[MSS_SKEY_SIZE + i] = pkey[i];

#ifdef MSS_SELFTEST
    // Assert
    // TODO
#endif

    return keys;
}

unsigned char *mss_sign(unsigned char skey[MSS_SKEY_SIZE], const unsigned char digest[2 * MSS_SEC_LVL], const unsigned char *pkey) {
    // Arrange
    /* Auxiliary variables */
    unsigned short index;
    struct mss_node node[3];
    unsigned char hash[LEN_BYTES(WINTERNITZ_N)];
    unsigned char ots[MSS_OTS_SIZE];

    mmo_t hash1, hash2;

    /* Merkle-tree variables */
    struct mss_state state;
    struct mss_node authpath[MSS_HEIGHT];

    unsigned char seed[LEN_BYTES(MSS_SEC_LVL)];

    unsigned char *signature = malloc(MSS_SIGNATURE_SIZE);

    // Act

    /* Initialization of Merkle–Damgård hash */
    //DM_init(&hash_dm);

    /* Initialization of Winternitz-MMO OTS */
    //MMO_init(&hash_mmo);

    deserialize_mss_skey(&state, &index, seed, skey);

    mss_sign_core(&state, seed, &node[0], (char *) digest, 2 * MSS_SEC_LVL, &hash1, &hash2, hash, index, &node[1], &node[2], ots, authpath, pkey);
    index++;

    serialize_mss_skey(state, index, seed, skey);
    //printf(">>>>>>>>>>skey\n%d\n", MSS_SKEY_SIZE);
    //unsigned int i;
    //for(i=0; i < MSS_SKEY_SIZE; i++)
    //		printf("%02X", skey[i]);
    serialize_mss_signature(ots, node[0], authpath, signature);
    //Assert
    return signature;
}

unsigned char mss_verify(const unsigned char signature[MSS_SIGNATURE_SIZE], const unsigned char pkey[MSS_PKEY_SIZE], const unsigned char digest[2 * MSS_SEC_LVL]) {
    // Arrange

    unsigned char verification = MSS_ERROR;

    /* Auxiliary varibles */
    struct mss_node v;
    unsigned char hash[LEN_BYTES(WINTERNITZ_N)];
    unsigned char ots[WINTERNITZ_L * LEN_BYTES(WINTERNITZ_SEC_LVL)];
    unsigned char aux[LEN_BYTES(WINTERNITZ_SEC_LVL)];

    mmo_t hash1, hash2;

    /* Merkle-tree variables */
    struct mss_node authpath[MSS_HEIGHT];

    // Act

    /* Initialization of Merkle–Damgård hash */
    //DM_init(&hash_dm);

    /* Initialization of Winternitz-MMO OTS */
    //MMO_init(&hash_mmo);

    deserialize_mss_signature(ots, &v, authpath, signature);

    verification = mss_verify_core(authpath, (char *) digest, 2 * MSS_SEC_LVL, &hash1, &hash2, hash, v.index, ots, aux, &v, pkey);

    //Assert
    return verification;
}


/***************************************************************************************************/
/* Serialization/Deserialization																   */

/***************************************************************************************************/

void serialize_mss_node(const struct mss_node node, unsigned char buffer[MSS_NODE_SIZE]) {
    unsigned int i, offset = 0;

    buffer[offset++] = node.height;
    buffer[offset++] = node.index & 0xFF;
    buffer[offset++] = (node.index >> 8) & 0xFF;

    for (i = 0; i < LEN_BYTES(MSS_SEC_LVL); i++)
        buffer[offset++] = node.value[i];
}

void deserialize_mss_node(struct mss_node *node, const unsigned char buffer[]) {
    unsigned int i, offset = 0;

    node->height = buffer[offset++];
    node->index = (buffer[offset++] & 0xFF);
    node->index = node->index | (buffer[offset++] << 8);

    for (i = 0; i < LEN_BYTES(MSS_SEC_LVL); i++)
        node->value[i] = buffer[offset++];
}

void serialize_mss_state(const struct mss_state state, const unsigned short index, unsigned char buffer[MSS_STATE_SIZE]) {
    unsigned int i, offset = 0;

    buffer[offset++] = index & 0xFF;
    buffer[offset++] = (index >> 8) & 0xFF;

    for (i = 0; i < MSS_TREEHASH_SIZE; i++)
        buffer[offset++] = state.treehash_state[i];

    buffer[offset++] = state.stack_index & 0xFF;
    buffer[offset++] = (state.stack_index >> 8) & 0xFF;

    for (i = 0; i < MSS_K - 1; i++) {
        buffer[offset++] = state.retain_index[i] & 0xFF;
        buffer[offset++] = (state.retain_index[i] >> 8) & 0xFF;
    }

    for (i = 0; i < MSS_TREEHASH_SIZE; i++) {
        buffer[offset++] = state.treehash_seed[i] & 0xFF;
        buffer[offset++] = (state.treehash_seed[i] >> 8) & 0xFF;
    }

    for (i = 0; i < MSS_TREEHASH_SIZE; i++) {
        serialize_mss_node(state.treehash[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_STACK_SIZE; i++) {
        serialize_mss_node(state.stack[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_RETAIN_SIZE; i++) {
        serialize_mss_node(state.retain[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_KEEP_SIZE; i++) {
        serialize_mss_node(state.keep[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_HEIGHT; i++) {
        serialize_mss_node(state.auth[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_TREEHASH_SIZE - 1; i++) {
        serialize_mss_node(state.store[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }
}

void deserialize_mss_state(struct mss_state *state, unsigned short *index, const unsigned char buffer[]) {
    int i, offset = 0;

    *index = (buffer[offset++] & 0xFF);
    *index = *index | (buffer[offset++] << 8);

    for (i = 0; i < MSS_TREEHASH_SIZE; i++)
        state->treehash_state[i] = buffer[offset++];

    state->stack_index = (buffer[offset++] & 0xFF);
    state->stack_index = state->stack_index | (buffer[offset++] << 8);


    for (i = 0; i < MSS_K - 1; i++)
        state->retain_index[i] = (buffer[offset++] & 0xFF);
    state->retain_index[i] = state->retain_index[i] | (buffer[offset++] << 8);

    for (i = 0; i < MSS_TREEHASH_SIZE; i++)
        state->treehash_seed[i] = (buffer[offset++] & 0xFF);
    state->treehash_seed[i] = state->treehash_seed[i] | (buffer[offset++] << 8);

    for (i = 0; i < MSS_TREEHASH_SIZE; i++) {
        deserialize_mss_node(&state->treehash[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_STACK_SIZE; i++) {
        deserialize_mss_node(&state->stack[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_RETAIN_SIZE; i++) {
        deserialize_mss_node(&state->retain[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_KEEP_SIZE; i++) {
        deserialize_mss_node(&state->keep[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_HEIGHT; i++) {
        deserialize_mss_node(&state->auth[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_TREEHASH_SIZE - 1; i++) {
        deserialize_mss_node(&state->store[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }
}

void serialize_mss_skey(const struct mss_state state, const unsigned short index, const unsigned char skey[LEN_BYTES(MSS_SEC_LVL)], unsigned char buffer[MSS_SKEY_SIZE]) {
    serialize_mss_state(state, index, buffer);

    unsigned int offset = MSS_STATE_SIZE, i;

    for (i = 0; i < LEN_BYTES(MSS_SEC_LVL); i++)
        buffer[offset++] = skey[i];
}

void deserialize_mss_skey(struct mss_state *state, unsigned short *index, unsigned char skey[LEN_BYTES(MSS_SEC_LVL)], const unsigned char buffer[]) {
    deserialize_mss_state(state, index, buffer);

    unsigned int offset = MSS_STATE_SIZE, i;

    for (i = 0; i < LEN_BYTES(MSS_SEC_LVL); i++)
        skey[i] = buffer[offset++];
}

void serialize_mss_signature(const unsigned char ots[MSS_OTS_SIZE], const struct mss_node v, const const struct mss_node authpath[MSS_HEIGHT], unsigned char *buffer) {
    /*
     * Serialization: v || authpath || ots
     *
     */
    unsigned int i, offset = 0;

    serialize_mss_node(v, buffer);
    offset += MSS_NODE_SIZE;

    for (i = 0; i < MSS_HEIGHT; i++) {
        serialize_mss_node(authpath[i], buffer + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_OTS_SIZE; i++)
        buffer[offset++] = ots[i];
}

void deserialize_mss_signature(unsigned char ots[MSS_OTS_SIZE], struct mss_node *v, struct mss_node authpath[MSS_HEIGHT], const unsigned char *signature) {
    int i, offset = 0;

    deserialize_mss_node(v, signature);
    offset += MSS_NODE_SIZE;

    for (i = 0; i < MSS_HEIGHT; i++) {
        deserialize_mss_node(&authpath[i], signature + offset);
        offset += MSS_NODE_SIZE;
    }

    for (i = 0; i < MSS_OTS_SIZE; i++)
        ots[i] = signature[offset++];
}

#endif // serialization/deserialization methods

#if defined(DEBUG) || defined(MSS_SELFTEST)

unsigned char _node_valid_index(const unsigned char height, const unsigned short pos) {
    unsigned char valid_height = 0;
    unsigned char valid_pos = 0;
    if (height >= 0 && height <= MSS_HEIGHT) {
        valid_height = 1;
        if ((pos >= 0) && (pos < (1 << (MSS_HEIGHT - height))))
            valid_pos = 1;
    }
    return (valid_height && valid_pos);
}

unsigned char _node_valid(const struct mss_node *node) {
    unsigned char valid_value_size = 0;
    if (sizeof (node->value) == LEN_BYTES(MSS_SEC_LVL))
        valid_value_size = 1;
    return (valid_value_size && _node_valid_index(node->height, node->index));
}

unsigned char _node_equal(const struct mss_node *node1, const struct mss_node *node2) {
    char equal = 0;
    if (node1->height == node2->height && node1->index == node2->index)
        equal = (memcmp(node1->value, node2->value, NODE_VALUE_SIZE) == 0);
    return equal;
}

unsigned char _is_left_node(const struct mss_node *node) {
    return ((node->index & 1) == 0);
}

unsigned char _is_right_node(const struct mss_node *node) {
    return ((node->index & 1) == 1);
}

unsigned char _node_brothers(const struct mss_node *left_node, const struct mss_node *right_node) {
    char brothers = 0;
    if (_node_valid(left_node) && _node_valid(right_node)) {
        if (left_node->height == right_node->height) {
            if ((_is_left_node(left_node) && _is_right_node(right_node)) && (right_node->index - left_node->index == 1))
                brothers = 1;
        }
    }
    return brothers;
}

/*******************************************************************************/
/* Auxiliary print for debugging											   */
/*******************************************************************************/

#ifdef DEBUG

void mss_node_print(const struct mss_node node) {
    printf("h=%d, pos=%d\n", node.height, node.index);
    Display("Node", node.value, NODE_VALUE_SIZE);
}

void print_stack(const struct mss_node stack[MSS_KEEP_SIZE], const unsigned short top) {
    unsigned short i;
    if (top == 0)
        printf(" empty\n");
    else {
        printf("\n");
        for (i = 0; i < top; i++) {
            printf("\nStack node: %d\n", i);
            mss_node_print(stack[i]);
        }
    }
}

void print_stack_push(const struct mss_node stack[MSS_KEEP_SIZE], const unsigned short top, const struct mss_node node, const unsigned char pre_condition) {
    if (pre_condition) {
        printf("----- _stack_push -----\n\n");
        printf("Stack before push:");
        print_stack(stack, top);
        printf("\nNode to push\n");
        mss_node_print(node);
    } else {
        printf("\nStack after push:");
        print_stack(stack, top);
        printf("-----------------------\n");
    }
    //getchar();
}

void print_stack_pop(const struct mss_node stack[MSS_KEEP_SIZE], const unsigned short top, const unsigned char pre_condition) {
    if (pre_condition) {
        printf("----- _stack_pop -----\n\n");
        printf("Stack before pop:");
        print_stack(stack, top);
    } else {
        printf("\nStack after pop:");
        print_stack(stack, top);
        printf("-----------------------\n");
    }
    //getchar();
}

void print_auth(const struct mss_state *state) {
    unsigned char i;
    // Print Auth
    printf("\nAuthentication Path\n");
    for (i = 0; i < MSS_HEIGHT; i++) {
        printf("Node[%d, %d]", state->auth[i].height, state->auth[i].index);
        Display("", state->auth[i].value, NODE_VALUE_SIZE);
    }
}

void print_treehash(const struct mss_state *state) {
    unsigned char i;
    // Print Treehash
    printf("\nTreehash\n");
    for (i = 0; i < MSS_TREEHASH_SIZE; i++) {
        printf("Node[%d, %d]", state->treehash[i].height, state->treehash[i].index);
        Display("", state->treehash[i].value, NODE_VALUE_SIZE);
    }
}

// Return the index of the authentication path for s-th leaf

void get_auth_index(unsigned short s, unsigned short auth_index[MSS_HEIGHT]) {
    unsigned char h;
    for (h = 0; h < MSS_HEIGHT; h++) {
        if (s % 2 == 0)
            auth_index[h] = s + 1;
        else

            auth_index[h] = s - 1;
        s >>= 1;
    }
}

void print_auth_index(unsigned short auth_index[MSS_HEIGHT - 1]) {
    printf("Expected index:\n");
    unsigned char h;
    for (h = MSS_HEIGHT - 1; h >= 0; h--)
        printf("\th = %d : n[%d][%d]\n", h, h, auth_index[h]);
}

void print_retain(const struct mss_state *state) {
    unsigned short index;
    printf("\nRetain\n");

    printf("height:\n");
    for (index = 0; index < MSS_RETAIN_SIZE; index++) {
        //printf("\tNode[%d, %d]", state->retain[index].height, state->retain[index].index);
        printf("0x%02x,", state->retain[index].height);
    }

    printf("\nindex:\n");
    for (index = 0; index < MSS_RETAIN_SIZE; index++) {
        printf("0x%04x,", state->retain[index].index);
    }

    printf("\nvalue:\n");
    for (index = 0; index < MSS_RETAIN_SIZE; index++) {
        display_value("", state->retain[index].value, NODE_VALUE_SIZE);
    }
}

#endif

#ifdef MSS_SELFTEST

#include "util.h"
#include "test.h"

int main(int argc, char *argv[]) {

    unsigned short i, ntest = 2;
    
    printf("\nParameters:  WINTERNITZ_n=%u, Tree_Height=%u, Treehash_K=%u, WINTERNITZ_w=%u \n\n", MSS_SEC_LVL, MSS_HEIGHT, MSS_K, WINTERNITZ_W);

    // Execution variables
    unsigned char seed[LEN_BYTES(MSS_SEC_LVL)] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
    unsigned char skey[MSS_SKEY_SIZE], pkey[MSS_PKEY_SIZE], *key_pair, signature[MSS_SIGNATURE_SIZE];
    char msg[] = "Hello, world!";

    unsigned short j;
    srand(time(NULL));

    for (j = 0; j < LEN_BYTES(MSS_SEC_LVL); j++) {
        seed[j] = rand() ^ j; // sample private key, this is not a secure, only for tests!
    }

    Display("seed for keygen: ", seed, LEN_BYTES(MSS_SEC_LVL));

    printf("Key generation... ");
    key_pair = mss_keygen(seed);
    memcpy(skey, key_pair, MSS_SKEY_SIZE);
    memcpy(pkey, key_pair + MSS_SKEY_SIZE, MSS_PKEY_SIZE);
    printf("Done!\n");

    printf("Signing %d messages... ", ntest);
    for (i = 0; i < ntest; i++)
        memcpy(signature, mss_sign(skey, (unsigned char *) msg, pkey), MSS_SIGNATURE_SIZE);
    printf("Done!\n");

    printf("Signature verification... ");
    assert(mss_verify(signature, pkey, (unsigned char *) msg));
    printf("Done!\n");

    return 0;
}
#endif //MSS_SELFTEST

#endif
