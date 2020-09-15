Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7O6QT5QKGQEBBM6BUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 67AC626AF6E
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:49 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id l17sf1694410wrw.11
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204669; cv=pass;
        d=google.com; s=arc-20160816;
        b=VaeSi3D/3Dpz2nQXmqycDgg0CB6CsC3skDBE25y1isTA3nKUXSvsLf7gH9jrjSZ5Uu
         6PEX9+OIZHrOEcrE1v66VEPIaam5dVBfNXMBf1xRO5XjA4WKbDttxbvcLOsz8iG0OF5S
         u9mtjLcwDBtPGmIRTKPxna+MuJWsepngGGmSzuMxA+LvKqtEJQ/DlQ0GtU6pCEAB1ANx
         /jj+E31QHh9abMwQPnbSYKq6Q8Dj6c5b613a7r/rgY0nz0nRoflsVYd5sjKC7yBIC6NO
         u1xogSq+/MizPrFkrziSznsyfcJ8mCmXRRF3DaXwe3JWidT3kIm5ffs3oXdfgp6oGg8Z
         RRjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=uOijC+mWA3hNU5N6qKkt8SpQbywsH2QilqXPlaIK2aU=;
        b=DeXxIX4Md0j+Kf0wSQ++DwCXGdnZA0phfeCFkm+MLJWKQBryFX+zosD7bwNT8qU+my
         34UsLcbgGr7eXqOa8fRsQosTcPvzhNkoGhJOTv2Z/HjiWXlAzB+FMBBa2IdMDYCoXTxu
         PgXpi9tmhKehsVou6gEFFH3OOHzMTrUE5Krc2Xzyhm9GxKx/G6P1w10+5iKm1PDJLtFh
         7hgFJgxgNJfy5rOip5Qfw/CUvPqlL0cN79EQ2t/YS3HaCRKLcENflv2YH+nwHKSp0ukf
         jprDq93nyLtJEBFDHTJK81qS9uGB5gYl6D9uJB2Ct9LDEyYFEuFspEGoHhy21HhvyXM+
         UJ5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fsTRc89Y;
       spf=pass (google.com: domain of 3fc9hxwokcwe9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fC9hXwoKCWE9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uOijC+mWA3hNU5N6qKkt8SpQbywsH2QilqXPlaIK2aU=;
        b=SXT51IUPkRJMtxRbEJsvy5ziVSAmBW9SIQfxFDDk16Sn+UbfdSkPrSvrti7/RvIOS5
         FBawNDXsz2/v9XcNkmcl8jfsVVt+lG1IUTwniC0nMYIxk/5So2v9qEdg0bUSx+GyyEN/
         IlPRrCEFQ0aB8reltUhSSEkbnvqB4D/Eh20qLiNrzwWVdRYUR3qi68mqlgHMpMSFvr65
         VXLQ+TuhWM5WJB36hFcaPkIxfg1UjP3fylgxa3V4zNlHrcRVZRjfAEhtVbCtUNnCcg9V
         aAiWlVZ/ExbaiJtTS/qbQzYfPBd/CqTh/6fA1y6xFvUUVxqkmk5WhPJChFPFNFe5s1Or
         gGgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uOijC+mWA3hNU5N6qKkt8SpQbywsH2QilqXPlaIK2aU=;
        b=hUjKPA+EF0qC+815sMyOB72TmpKYjKxDTyz3SF3nRBXd3v34towfl6JwIHW+2tmEF0
         SLEONxxzMZ0hRi2xq1bhT7O5B5BOiwgob1MIyZXxdWI+xhUwdJmcVeLBYGYst2A1fUrg
         5nGRR+l9bTEE0ATH3qsh+XSnUCIyQ0hwAjinp/OD3wVGmdenDHB8/CQrCbVqyJv2A7Hw
         rkFs1VUWhYoGz9Av2LuHiNbOOYwkmBSnze/LfNx/tSK8mnzn6bW1184swY2WjQaYR4RC
         7ybR40odA5A1nBpbCKaMex+LiH4GK6nIPG9GGDBrgLxtOLqqT+cwfqhxSZRuoBCxCeh8
         7Srg==
X-Gm-Message-State: AOAM533TxfpHQQ6w4XTYX+1U33b1U+LmzxWs7CRfgSf+jTi29Mq6Nr/o
	qDphYlsffd7Ju0w5JLLdwuM=
X-Google-Smtp-Source: ABdhPJy6zNLQ/5z21ZxqaHjl23KI0jGGNFxkN6Wwa5iYwRiTnJJHUg6pIYvG01/wsUhsIom5xegzLA==
X-Received: by 2002:a5d:4910:: with SMTP id x16mr25218823wrq.204.1600204669162;
        Tue, 15 Sep 2020 14:17:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls352749wrm.1.gmail; Tue, 15 Sep
 2020 14:17:48 -0700 (PDT)
X-Received: by 2002:a05:6000:11c5:: with SMTP id i5mr23784495wrx.18.1600204668417;
        Tue, 15 Sep 2020 14:17:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204668; cv=none;
        d=google.com; s=arc-20160816;
        b=x/vTrxPOcFJtANEZAFGf7RSBQbeJ8l1j8KlJCpetnUBBQAIb9a/FDdVumanXyKitwK
         +19E0dt71xppdNb17x/dGMqSvU4krCoRceOjMIkvGPBdEtYdCkh/M7XfdJZJjW1CBt7u
         6vfoOcDi90CtVrZ7Zcms5s8Xd5jz0XmDAhXMm4pXAuA2dylSsqWv86Inpl49t1T/8fzJ
         Kq2hmwyzW49dP4c/e16NyyTVfAX9lJQPtaGwQp01udRmlbdc/Oz2rH0rlBiwzxSXt4K6
         hS4GrlpA7PTkNx/KZefDb8kvtC5mKjfbanPo1U1znnfJpjpJjSkHlidq03Js33fyRDLm
         SO2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=OJ/8AnntxXTECtkQTOaxjfZECPzBTRORy6i2yS83kOo=;
        b=pyey4jBXWsOevaFn69ePgCEYULTadIUErDzAkzE8i36LvfYjqBOcKWqH4n/QxMZnB7
         Al0LWOQLk3cC2e6JIYfR8RSKbOB2y0ZtQh3XURGBs32vqMF5ZXhj+dJauyjarlaa4zjr
         PaSIpxiv7a77CGOiJseQ3nav/FCBmr7BOf2h480aM22PynGNKf1982DZEgV2PrJsELpE
         BUY62kYdkkcJXvDK+B1KAIF/g5DFkeABcxJ6nRuwGY9ha9aoZkiKr85cg9kfPJ2alQDP
         kPLc8UcyfKyzsjnvlJ+I7tuBKL4dDg5MN4g0BGGpX1NQ7ucmyVeP5aKqvwk61FyDkHR/
         Tajw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fsTRc89Y;
       spf=pass (google.com: domain of 3fc9hxwokcwe9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fC9hXwoKCWE9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id b1si22834wmj.1.2020.09.15.14.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fc9hxwokcwe9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id b20so392742wmj.1
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:48 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2283:: with SMTP id
 3mr1188256wmf.37.1600204668051; Tue, 15 Sep 2020 14:17:48 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:17 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <f511f01a413c18c71ba9124ee3c341226919a5e8.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 35/37] kasan, slub: reset tags when accessing metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fsTRc89Y;       spf=pass
 (google.com: domain of 3fc9hxwokcwe9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3fC9hXwoKCWE9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

SLUB allocator accesses metadata for slab objects, that may lie
out-of-bounds of the object itself, or be accessed when an object is freed.
Such accesses trigger tag faults and lead to false-positive reports with
hardware tag-based KASAN.

Software KASAN modes disable instrumentation for allocator code via
KASAN_SANITIZE Makefile macro, and rely on kasan_enable/disable_current()
annotations which are used to ignore KASAN reports.

With hardware tag-based KASAN neither of those options are available, as
it doesn't use compiler instrumetation, no tag faults are ignored, and MTE
is disabled after the first one.

Instead, reset tags when accessing metadata.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I39f3c4d4f29299d4fbbda039bedf230db1c746fb
---
 mm/page_poison.c |  2 +-
 mm/slub.c        | 25 ++++++++++++++-----------
 2 files changed, 15 insertions(+), 12 deletions(-)

diff --git a/mm/page_poison.c b/mm/page_poison.c
index 34b9181ee5d1..d90d342a391f 100644
--- a/mm/page_poison.c
+++ b/mm/page_poison.c
@@ -43,7 +43,7 @@ static void poison_page(struct page *page)
 
 	/* KASAN still think the page is in-use, so skip it. */
 	kasan_disable_current();
-	memset(addr, PAGE_POISON, PAGE_SIZE);
+	memset(kasan_reset_tag(addr), PAGE_POISON, PAGE_SIZE);
 	kasan_enable_current();
 	kunmap_atomic(addr);
 }
diff --git a/mm/slub.c b/mm/slub.c
index 68c02b2eecd9..8e134ca3a6fb 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -249,7 +249,7 @@ static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
 {
 #ifdef CONFIG_SLAB_FREELIST_HARDENED
 	/*
-	 * When CONFIG_KASAN_SW_TAGS is enabled, ptr_addr might be tagged.
+	 * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tagged.
 	 * Normally, this doesn't cause any issues, as both set_freepointer()
 	 * and get_freepointer() are called with a pointer with the same tag.
 	 * However, there are some issues with CONFIG_SLUB_DEBUG code. For
@@ -275,6 +275,7 @@ static inline void *freelist_dereference(const struct kmem_cache *s,
 
 static inline void *get_freepointer(struct kmem_cache *s, void *object)
 {
+	object = kasan_reset_tag(object);
 	return freelist_dereference(s, object + s->offset);
 }
 
@@ -304,6 +305,7 @@ static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
 	BUG_ON(object == fp); /* naive detection of double free or corruption */
 #endif
 
+	freeptr_addr = (unsigned long)kasan_reset_tag((void *)freeptr_addr);
 	*(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
 }
 
@@ -538,8 +540,8 @@ static void print_section(char *level, char *text, u8 *addr,
 			  unsigned int length)
 {
 	metadata_access_enable();
-	print_hex_dump(level, text, DUMP_PREFIX_ADDRESS, 16, 1, addr,
-			length, 1);
+	print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
+			16, 1, addr, length, 1);
 	metadata_access_disable();
 }
 
@@ -570,7 +572,7 @@ static struct track *get_track(struct kmem_cache *s, void *object,
 
 	p = object + get_info_end(s);
 
-	return p + alloc;
+	return kasan_reset_tag(p + alloc);
 }
 
 static void set_track(struct kmem_cache *s, void *object,
@@ -583,7 +585,8 @@ static void set_track(struct kmem_cache *s, void *object,
 		unsigned int nr_entries;
 
 		metadata_access_enable();
-		nr_entries = stack_trace_save(p->addrs, TRACK_ADDRS_COUNT, 3);
+		nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
+						TRACK_ADDRS_COUNT, 3);
 		metadata_access_disable();
 
 		if (nr_entries < TRACK_ADDRS_COUNT)
@@ -747,7 +750,7 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct page *page,
 
 static void init_object(struct kmem_cache *s, void *object, u8 val)
 {
-	u8 *p = object;
+	u8 *p = kasan_reset_tag(object);
 
 	if (s->flags & SLAB_RED_ZONE)
 		memset(p - s->red_left_pad, val, s->red_left_pad);
@@ -777,7 +780,7 @@ static int check_bytes_and_report(struct kmem_cache *s, struct page *page,
 	u8 *addr = page_address(page);
 
 	metadata_access_enable();
-	fault = memchr_inv(start, value, bytes);
+	fault = memchr_inv(kasan_reset_tag(start), value, bytes);
 	metadata_access_disable();
 	if (!fault)
 		return 1;
@@ -873,7 +876,7 @@ static int slab_pad_check(struct kmem_cache *s, struct page *page)
 
 	pad = end - remainder;
 	metadata_access_enable();
-	fault = memchr_inv(pad, POISON_INUSE, remainder);
+	fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
 	metadata_access_disable();
 	if (!fault)
 		return 1;
@@ -1118,7 +1121,7 @@ void setup_page_debug(struct kmem_cache *s, struct page *page, void *addr)
 		return;
 
 	metadata_access_enable();
-	memset(addr, POISON_INUSE, page_size(page));
+	memset(kasan_reset_tag(addr), POISON_INUSE, page_size(page));
 	metadata_access_disable();
 }
 
@@ -2884,10 +2887,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 		stat(s, ALLOC_FASTPATH);
 	}
 
-	maybe_wipe_obj_freeptr(s, object);
+	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
 
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
-		memset(object, 0, s->object_size);
+		memset(kasan_reset_tag(object), 0, s->object_size);
 
 	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
 
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f511f01a413c18c71ba9124ee3c341226919a5e8.1600204505.git.andreyknvl%40google.com.
