Return-Path: <kasan-dev+bncBAABBMFVSKWAMGQEGNXEEVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AEFC81BF5F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:06:09 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3368abe10c5sf585338f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:06:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189169; cv=pass;
        d=google.com; s=arc-20160816;
        b=epezDFR971wclAeipVm26wJf/nnNiZyz457HgMtas4Ddq2JIiy/MsfQDzCL2Jo66kO
         lcgz9jJVjlMbf/7nu4jN7/h8SXilr90xWJZ/JnNuFsDMeG2KMd/I2qnlJDHVnvuHFD86
         9+Psa4L+9ONdgmgkkFMFU4EtrfF+yrRdPI9EOzj/Y8KLYkTkfJ44W11PJOPBOhce4VDB
         vBEJkprhH5XfmX1NKVZRgXqG/FqEgler2Mm3gQLYW36qVrdHKzGgDHbrwHy596Qqq8FP
         Bpuh1TZfZi1x/fiTtK34JzjoX6TgffnLw2kOGgVC/v8oTeFNgfwZoJC7Xji8IkoRhn+l
         1XCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lg3EnhvMyphLi/tcGt5KW0sLi5Hu/P8thYIaLNKAe/I=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=vGSAqgxe/vReXPl6fw60cVjfniUoF+rAodnwfTbRaJiQz1EOL4NIdi9cwDrW6fZWDz
         bLUwQIg8fGS1YJNmDw2WZs9G9YygIKF7DTx+K6lx6HOGX1Gt9ihx7WavgQWgFhGd9D4q
         zAHWfjeKphDyxn+fY7Pwb5pymmniYSMM740BQRPspKmUPEAPOZn96kKl8/MEyp5+6dE/
         0IR9gaEm2FD50gBMvEwn+xgFKDx3fzTbYCCsFnwsOPocQdhwIQweS/L2IbUz1oI8g7zx
         9D3IXZmrbODU5mRgjd7VhNbIWOAae2NgHWPKuyCJIkCOgsZd/N6kC4Usg8zdAHBJD+f2
         pwdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KmqU694Z;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189169; x=1703793969; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lg3EnhvMyphLi/tcGt5KW0sLi5Hu/P8thYIaLNKAe/I=;
        b=PtjmaOBLpneIAPF5TALLesC2iasYPTwc58zOS7sWKLiFcKvCEgs4wNS4zNms47wKwN
         gve/AYqIl0EFdPTSDUGQ2pmRDO2OtExNcTRellCWs6qdxBcr95uYdAZSiBuleeGIrD5S
         V0NiOFOL1qAGW72WnWymByEbQptbfqZXNLlS/K+P/oxveGpd8AGlbh9AKxQ+K1zF5H8/
         kDfCVQBjGo3LzBDDX7ibfPv5lN5EwW8NLc9LQ6bt8DSz0UwHWdVYO4AMfxhVvLQ7UeSb
         HoSmO+bTZ4ZDDkyGzfoJxbbDW7TxQ5kqhqon0DgOFXTOzjAXaDbfPmm28A23GAXCF7AI
         E7kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189169; x=1703793969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lg3EnhvMyphLi/tcGt5KW0sLi5Hu/P8thYIaLNKAe/I=;
        b=BNFO4pFxZR8pcxszNdhq5rzpgCZQAzmVAfMFDwX3iIfaEME2c68e+LvB5CiSRW6V/L
         CdwD4MbRrQKGyOCEZxTuw4QltcOF4eeBP1WxdNp6vOrLgrfJBX0Afj63XmJ0fTLOuLf3
         ILa8PMh/BZaxSxe2CPS7z5ouNz7a8pI+Z4h2wbD3R/SyXd8yblRNvTsU0IEtaKQe+Mg3
         LBHr5+JhD9ScKDtjXql+iBhu9e8IPfsgFzTePQeA3aob9zDVUsoqIopghyZQg44ZWZ3m
         4ars1aVn5l9dvfpFHyU5MFcWYwMjHG4dFjgDZijdiAYtKJATnAtXtIG54mTQOpXVbzIS
         T9Ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywmi3lC4PSy5763KTe3rlwYZKbn08SvFvEz8xPP9AdrpxeWMc13
	ByMYSfRGwevQKLf001LzRFA=
X-Google-Smtp-Source: AGHT+IGrKM36q/sW1M8ARRLciNhhUkzEV5f0CAxCb/gWB+XGbzLxLSRLcZvTdpR+eI7nkIOgkjB4kw==
X-Received: by 2002:adf:e74d:0:b0:336:7bb5:42fd with SMTP id c13-20020adfe74d000000b003367bb542fdmr143182wrn.174.1703189168836;
        Thu, 21 Dec 2023 12:06:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f48c:0:b0:336:4f85:e0d0 with SMTP id l12-20020adff48c000000b003364f85e0d0ls537176wro.1.-pod-prod-02-eu;
 Thu, 21 Dec 2023 12:06:07 -0800 (PST)
X-Received: by 2002:a5d:5605:0:b0:336:5fae:2328 with SMTP id l5-20020a5d5605000000b003365fae2328mr145660wrv.22.1703189167378;
        Thu, 21 Dec 2023 12:06:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189167; cv=none;
        d=google.com; s=arc-20160816;
        b=W6lNHrhDXmLyLV5IJge6cGk7ZaWU8WuFkAXhl1pLfm6qudy6/A1owdFzvJDvL9TxTf
         mFPi6beLv0M6DARyCFTWaNKTNR1oj++ZfuQDPUAh4dwHBTyg9TUJ8nqAsBUgAGdedYJa
         tQP45O5MOoHUxfFrTTu4SxU4oQhYPnM7NG3W5otC0/kqAfzA8yHkKxUseoLLSU/Hnhy5
         nnw47opNKAyVxDnVxwCmadYNAo6wBO8e17jmNsLSzNzvREQZ9jLFIDtZg/B29d9ab4Nk
         RkIzweyhbtcfvFrPAG4v6nXhIPLWSrPH8q4PMmULpdeq+5E7wxBKNu2ZPr0wnKDGAoBu
         Jm2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=itOhYdVtqZdvAR7o0Q16gEQdZUJ+zDuxto8wg6YMX5U=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=qEB//yct3LrWrDpPskjOmB2qoaKUHCuABQSZlgkF8p58Grid2D2WjO4FOYOJZsdzq2
         1u2oCRQyyql+bIJckdVNV/ek3LuPDD6VyF5nfhVCbvxH0Fb06NpDdisYjHXcf9GtTWSt
         h0bsrqHzClJ2ID9oDll7azwpmjWwNXO2OdaUCiIBD/zoUf4kLfaa7Uphh5zcWiAa8+kN
         XU5qadDnEdhdIdOtGobhglgQEWRcEy/+we6WzPv1rOTC9DVQg1NtdDP8BkDpVeq9kRsm
         6zY8EHwKuNt0l/SyAXYzGv7BlFB+d1HmMMzklEXVDAOZ3l7a7wdi/5kzN/GXtXXPlmy8
         RH0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KmqU694Z;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta0.migadu.com (out-180.mta0.migadu.com. [2001:41d0:1004:224b::b4])
        by gmr-mx.google.com with ESMTPS id r14-20020a5d498e000000b0033673ddbd3fsi101590wrq.2.2023.12.21.12.06.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:06:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b4 as permitted sender) client-ip=2001:41d0:1004:224b::b4;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 10/11] kasan: remove SLUB checks for page_alloc fallbacks in tests
Date: Thu, 21 Dec 2023 21:04:52 +0100
Message-Id: <c82099b6fb365b6f4c2c21b112d4abb4dfd83e53.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KmqU694Z;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b4 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

From: Andrey Konovalov <andreyknvl@google.com>

A number of KASAN tests rely on the fact that calling kmalloc with a size
larger than an order-1 page falls back onto page_alloc.

This fallback was originally only implemented for SLUB, but since
commit d6a71648dbc0 ("mm/slab: kmalloc: pass requests larger than order-1
page to page allocator"), it is also implemented for SLAB.

Thus, drop the SLUB checks from the tests.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c | 26 ++------------------------
 1 file changed, 2 insertions(+), 24 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 496154e38965..798df4983858 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -215,7 +215,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 
 /*
  * Check that KASAN detects an out-of-bounds access for a big object allocated
- * via kmalloc(). But not as big as to trigger the page_alloc fallback for SLUB.
+ * via kmalloc(). But not as big as to trigger the page_alloc fallback.
  */
 static void kmalloc_big_oob_right(struct kunit *test)
 {
@@ -233,8 +233,7 @@ static void kmalloc_big_oob_right(struct kunit *test)
 /*
  * The kmalloc_large_* tests below use kmalloc() to allocate a memory chunk
  * that does not fit into the largest slab cache and therefore is allocated via
- * the page_alloc fallback for SLUB. SLAB has no such fallback, and thus these
- * tests are not supported for it.
+ * the page_alloc fallback.
  */
 
 static void kmalloc_large_oob_right(struct kunit *test)
@@ -242,8 +241,6 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
-	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
-
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -258,8 +255,6 @@ static void kmalloc_large_uaf(struct kunit *test)
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
-	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
-
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
@@ -272,8 +267,6 @@ static void kmalloc_large_invalid_free(struct kunit *test)
 	char *ptr;
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 10;
 
-	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
-
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -407,18 +400,12 @@ static void krealloc_less_oob(struct kunit *test)
 
 static void krealloc_large_more_oob(struct kunit *test)
 {
-	/* page_alloc fallback is only implemented for SLUB. */
-	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
-
 	krealloc_more_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 201,
 					KMALLOC_MAX_CACHE_SIZE + 235);
 }
 
 static void krealloc_large_less_oob(struct kunit *test)
 {
-	/* page_alloc fallback is only implemented for SLUB. */
-	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
-
 	krealloc_less_oob_helper(test, KMALLOC_MAX_CACHE_SIZE + 235,
 					KMALLOC_MAX_CACHE_SIZE + 201);
 }
@@ -1144,9 +1131,6 @@ static void mempool_kmalloc_large_uaf(struct kunit *test)
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 1;
 	void *extra_elem;
 
-	/* page_alloc fallback is only implemented for SLUB. */
-	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
-
 	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
 
 	mempool_uaf_helper(test, &pool, false);
@@ -1215,9 +1199,6 @@ static void mempool_kmalloc_large_double_free(struct kunit *test)
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 1;
 	char *extra_elem;
 
-	/* page_alloc fallback is only implemented for SLUB. */
-	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
-
 	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
 
 	mempool_double_free_helper(test, &pool);
@@ -1272,9 +1253,6 @@ static void mempool_kmalloc_large_invalid_free(struct kunit *test)
 	size_t size = KMALLOC_MAX_CACHE_SIZE + 1;
 	char *extra_elem;
 
-	/* page_alloc fallback is only implemented for SLUB. */
-	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB);
-
 	extra_elem = mempool_prepare_kmalloc(test, &pool, size);
 
 	mempool_kmalloc_invalid_free_helper(test, &pool);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c82099b6fb365b6f4c2c21b112d4abb4dfd83e53.1703188911.git.andreyknvl%40google.com.
