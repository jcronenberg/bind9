/*
 * Copyright (C) 1999 Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

 /* $Id: tkey_249.c,v 1.1 1999/02/04 02:09:04 marka Exp $ */

 /* draft-ietf-dnssec-tkey-01.txt */

#ifndef RDATA_GENERIC_TKEY_249_H
#define RDATA_GENERIC_TKEY_249_H

static dns_result_t
fromtext_tkey(dns_rdataclass_t class, dns_rdatatype_t type,
		  isc_lex_t *lexer, dns_name_t *origin,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_token_t token;

	REQUIRE(type == 249);
	
	class = class;		/*unused*/
	origin = origin;	/*unused*/
	downcase = downcase;	/*unused*/


	/* Inception */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* Expiration */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* Mode */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Error */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Signature Size */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Signature */
	RETERR(base64_tobuffer(lexer, target, token.value.as_ulong));

	/* Other Len */
	RETERR(gettoken(lexer, &token, isc_tokentype_number, ISC_FALSE));
	if (token.value.as_ulong > 0xffff)
		return (DNS_R_RANGE);
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Other Data */
	return (base64_tobuffer(lexer, target, token.value.as_ulong));
}

static dns_result_t
totext_tkey(dns_rdata_t *rdata, dns_name_t *origin, isc_buffer_t *target) {
	isc_region_t sr;
	isc_region_t sigr;
	char buf[sizeof "4294967295 "];	
	unsigned long n;

	REQUIRE(rdata->type == 249);

	origin = origin;	/*unused*/

	dns_rdata_toregion(rdata, &sr);

	/* Inception */
	n = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Error */
	n = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Mode */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Error */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Signature Size */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Signature */
	REQUIRE(n <= sr.length);
	sigr = sr;
	sigr.length = n;
	RETERR(base64_totext(&sigr, target));
	RETERR(str_totext(" ", target));
	isc_region_consume(&sr, n);

	/* Other Size */
	n = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	sprintf(buf, "%lu ", n);
	RETERR(str_totext(buf, target));

	/* Other */
	return (base64_totext(&sr, target));
}

static dns_result_t
fromwire_tkey(dns_rdataclass_t class, dns_rdatatype_t type,
		  isc_buffer_t *source, dns_decompress_t *dctx,
		  isc_boolean_t downcase, isc_buffer_t *target)
{
	isc_region_t sr;
	unsigned long n;

	REQUIRE(type == 249);
	
	class = class;		/*unused*/
	dctx = dctx;		/*unused*/
	downcase = downcase;	/*unused*/
	
	isc_buffer_active(source, &sr);
	/* 
	 * Inception: 4
	 * Expiration: 4
	 * Mode: 2
	 * Error: 2
	 */
	if (sr.length < 12)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, 12));
	isc_region_consume(&sr, 12);
	isc_buffer_forward(source, 12);

	/* Signature Length + Signature */
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	n = uint16_fromregion(&sr);
	if (sr.length < n + 2)
		return (DNS_R_UNEXPECTEDEND);
	RETERR(mem_tobuffer(target, sr.base, n + 2));
	isc_region_consume(&sr, n + 2);
	isc_buffer_forward(source, n + 2);

	/* Other Length + Other */
	if (sr.length < 2)
		return (DNS_R_UNEXPECTEDEND);
	n = uint16_fromregion(&sr);
	if (sr.length < n + 2)
		return (DNS_R_UNEXPECTEDEND);
	isc_buffer_forward(source, n + 2);
	return (mem_tobuffer(target, sr.base, n + 2));
}

static dns_result_t
towire_tkey(dns_rdata_t *rdata, dns_compress_t *cctx, isc_buffer_t *target) {
	isc_region_t sr;

	REQUIRE(rdata->type == 249);

	cctx = cctx;	/*unused*/

	dns_rdata_toregion(rdata, &sr);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static int
compare_tkey(dns_rdata_t *rdata1, dns_rdata_t *rdata2) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->class == rdata2->class);
	REQUIRE(rdata1->type == 249);
	
	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (compare_region(&r1, &r2));
}

static dns_result_t
fromstruct_tkey(dns_rdataclass_t class, dns_rdatatype_t type,
		    void *source, isc_buffer_t *target) {

	REQUIRE(type == 249);
	
	class = class;	/*unused*/
	
	source = source;
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}

static dns_result_t
tostruct_tkey(dns_rdata_t *rdata, void *target) {

	REQUIRE(rdata->type == 249);
	
	target = target;

	return (DNS_R_NOTIMPLEMENTED);
}
#endif	/* RDATA_GENERIC_TKEY_249_H */
