#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Simple TLV (Type-Length-Value) packet parser */

#define MAX_FIELDS   16
#define HEADER_MAGIC 0xDEAD

typedef struct {
    uint16_t type;
    uint16_t length;
    char    *value;
} TLVField;

typedef struct {
    uint16_t  magic;
    uint8_t   num_fields;
    TLVField  fields[MAX_FIELDS];
} Packet;

/* Allocate a buffer for a field value.
 * BUG: length is attacker-controlled; multiplying by 2 can overflow. */
char *alloc_field_value(uint16_t length) {
    /* CWE-190: when length >= 32768, length * 2 wraps around to a small value */
    uint16_t alloc_size = length * 2;
    char *buf = (char *)malloc(alloc_size);
    return buf;   /* CWE-476 risk: NULL return is not checked by callers */
}

/* Copy raw data bytes into a field value buffer. */
void fill_field(TLVField *field, const char *data, uint16_t length) {
    /* CWE-787: writes length*2 bytes; if alloc_size wrapped, this overflows the buffer */
    memcpy(field->value, data, (size_t)length * 2);
}

/* Parse one TLV record from raw bytes.
 * Returns number of bytes consumed, or -1 on error. */
int parse_tlv(const char *buf, int buf_len, TLVField *out) {
    if (buf_len < 4) return -1;
    out->type   = *(uint16_t *)buf;
    out->length = *(uint16_t *)(buf + 2);
    /* CWE-125: no check that buf_len >= 4 + out->length before reading value bytes */
    out->value  = alloc_field_value(out->length);
    /* CWE-476: out->value may be NULL if malloc failed; fill_field will crash */
    fill_field(out, buf + 4, out->length);
    return 4 + out->length;
}

/* Build a human-readable summary into the caller-supplied buffer. */
void summarize_packet(const Packet *pkt, char *out, int out_len) {
    char tmp[64];
    int  offset = 0;
    for (int i = 0; i < pkt->num_fields; i++) {
        /* CWE-134: field->value is attacker-controlled and used as a format string */
        int written = snprintf(tmp, sizeof(tmp), pkt->fields[i].value);
        /* CWE-787: offset is not checked against out_len before writing */
        memcpy(out + offset, tmp, written);
        offset += written;
    }
    out[offset] = '\0';
}

/* Validate magic, parse all fields, and return a heap-allocated summary string.
 * Caller must free the returned pointer. */
char *process_packet(const char *raw, int raw_len) {
    if (raw_len < 3) return NULL;
    Packet *pkt = (Packet *)malloc(sizeof(Packet));
    /* CWE-476: NULL not checked before dereferencing pkt on the next line */
    pkt->magic      = *(uint16_t *)raw;
    pkt->num_fields = (uint8_t)raw[2];
    if (pkt->magic != HEADER_MAGIC || pkt->num_fields > MAX_FIELDS) {
        free(pkt);
        return NULL;
    }
    int pos = 3;
    for (int i = 0; i < pkt->num_fields; i++) {
        int consumed = parse_tlv(raw + pos, raw_len - pos, &pkt->fields[i]);
        if (consumed < 0) {
            /* CWE-401: field->value buffers allocated in earlier iterations are leaked */
            free(pkt);
            return NULL;
        }
        pos += consumed;
    }
    char *summary = (char *)malloc(256);
    summarize_packet(pkt, summary, 256);
    /* CWE-401: all pkt->fields[i].value buffers are leaked before free(pkt) */
    free(pkt);
    return summary;
}
