Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGFO6D6QKGQEUQFGAUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C6EE2C1561
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:10:01 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id b15sf650564lfb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:10:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162201; cv=pass;
        d=google.com; s=arc-20160816;
        b=uY07RaeU6gcFlHfhEI2u23DF4Y5Jah5L+vApI427z86iK9sM7BIdYLPFjP65Xc2WpF
         CLHiESeEzV3lQHcnbPmf1P6Fkob2Yf28uhAvKhK4o2xXSDLEj6WEs3ysOlvmjBMxvk+T
         urD8j4bSTCWFDIElAju0zo5FJWAVUt74mjvLpTEsmY2Lj5lschy2zr1+NrujMchHKDki
         B5/F93/4Ohl+7qSLllSeQi2s1TkrOv+kPNjvDtrBonK8tRVvdZqObJ9QM03IxHYWUCxD
         cASW198CzZBgvUTLhRcmJbxHmiLC9MSSeDakjHOJ/ugInYiwNGbq1ZeThBc5x9QCYkAE
         w7eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=MM50oj3QuVgudSz5jTBhaj8B+LktvOHwVoKKfqORxsQ=;
        b=CVs4dHnqA7eDWy+k+L17L0avWyaCwgGO4PhjRGpw690ht0MBYNCeMOnVCOr/nYtRno
         1Q79bdbyOzmPXpEgNd9K/NxzfU7p8pIXRmgiHzCHEP/B7ia6HGpeXGIF5dVj7gpL7glR
         fYCDQ4fWDcd5krd8EqSXchj1pmaHbevEfXMmC2MseGUut9kau8oWpO0ZPEd2UolYSBQy
         0xfQCtXoNhWqfmYibnF6mBWeW39h8KcBFuMkRCNAst+S8u+SvNQzwRI2BI5iMRjZg+Ni
         fhSuBFXxqjTRaddqsXl/4GMXxXN+ymqDDs1iu/oCjX4UHZtb5gRYrRqdCEdGGJr3AFFv
         +Lgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QNShjMEw;
       spf=pass (google.com: domain of 3fxe8xwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Fxe8XwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MM50oj3QuVgudSz5jTBhaj8B+LktvOHwVoKKfqORxsQ=;
        b=p4RQ08y1fOoTZxI7746NfpxnzSjfecbbdyfok3YnrpXwGH0/JDUqDW9DOlHfPdMg85
         QBcsiaHnTVXoRrz4Z0cjAEeihLyls+hpO2yCOTJLUsHj5pggZY5ffvYggVF15WvVOJnv
         yrNN19xJFSp1xwltNNN3tHqBvWBh1t0Nw97RNsxUODLtIGL4UrYT0Xzg2T7v2ZHUVGJb
         BfgmDzoeHq310btVBM87T5MLa9g7lXy9FC7reirvVM7KXBF4Wfakbh/2g5jiI3vNnxp+
         f1rD3g4qb1/vWPDq0ErOYQG8/E1XNJhaiUNrYcFte4sXPDt26aQtcUTDAsW3jppqaxBB
         w4fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MM50oj3QuVgudSz5jTBhaj8B+LktvOHwVoKKfqORxsQ=;
        b=E5SgDRisdbD6+6VQFJjFUy9fXxCfrcA92pDsHIBeEAGyuM9hV2dm9zOx+o26izfrs/
         Y/1SLVwRr3WJTlszCDhIZXjEovhjzi73/SOzoWL8+NedWJepYlIpfSoSkJa81Gban1N6
         Lz8J8emKlkGn/11iOYhDlELzXF8J8vXKHaaOSn6az6ChWRxvbXAh35V5uxMX+BOsEzcL
         j3LaCEO2zgsKwb/oEj4aAsGB5bDsXnczpVQUAw/xgrXCjFwc/SngqG7lVWS2VwvI7osr
         X7bmt0obfZGidlxaCvsBG99DyZPSWgHQfUtOx5tvhWbz3O+JnwXaaeB9KxKOeGPmy0ff
         Wbyg==
X-Gm-Message-State: AOAM533MSMmIcPhpGpLp1OFwgGQe+niKAJ9igJd7/df5wI1g+mhIb/1l
	tbHIbGbEhvPiYMW91BxAMrI=
X-Google-Smtp-Source: ABdhPJzhyHiuTNsmc0FF2hnTQ5d+9sDMn6qY8eveaGLYZ1agF4I7SPnB1aC69g7H0As/FRVVlkLkLg==
X-Received: by 2002:a19:7f02:: with SMTP id a2mr367263lfd.48.1606162200893;
        Mon, 23 Nov 2020 12:10:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9059:: with SMTP id n25ls609851ljg.3.gmail; Mon, 23 Nov
 2020 12:10:00 -0800 (PST)
X-Received: by 2002:a2e:83c7:: with SMTP id s7mr449235ljh.181.1606162199988;
        Mon, 23 Nov 2020 12:09:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162199; cv=none;
        d=google.com; s=arc-20160816;
        b=gV3FzwMEyTEG+aM7l2HeUqcOMOHyzyxKz2P4GNXOr3e35F5q5Z5oDtgMUfBSUjUyzH
         3tRP2SR24KTutpeTZ7MgW0E6SVyFVsCmI7veNBitnY9s4WLuZyaEzcbZ3mPxwYmmDeiF
         97HTKtDGK155+9Ka3CSihdoiYWe832Kx07UQD98gqlxg0Mjcj45NNEzX1VJIon8zPIpX
         Vht+pwgwIr4ZWy6MLIMOFiB9/7V4ERpG1XpEMAaEUhQicZFyNGmYjw7zjpE3oW7T52VV
         0uUyfRLHgqZ+HVhAdaTw8xN7MLox0SoIxe1YRoESbLI1u1pLF9RhgYrHp1nV26sI0rst
         C2BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=xPncFRf4Ib9dqqrvVPPr1Kkbz3E0xEx6JscY8zPs/c0=;
        b=hkk9imAd2gp/gZrU4PTqIhNyGm8hfH/7cUn3ptSKqMWmySpfxhf2x7u7xJkiZsDrz1
         PVfKHYPb0YfgtzfKWry+/hOhVT4NwO8Dh4RqLtXdOBfgR4NyqDf6sq1zRnADs0EXRMYj
         XOCrGOppbc0uSqeJH/zZY6Qus5KSEODvt4ZqE0bksgDRM06BV+i/+WdrCujThpAnMbzP
         JbwbalOrbzRHfI95byyftfY+Zd9kTHUpd0bQAXXpzEz+XAjM/sSYRjlJgHIXEwP+4yCn
         cfPs/7EL3Do9hWBFWxtXXhHYnPpxXuUUiTwU9l3IdPdm/SQd9Puo5ldnt4lbY+If5s25
         vRdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QNShjMEw;
       spf=pass (google.com: domain of 3fxe8xwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Fxe8XwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id y84si392848lfa.6.2020.11.23.12.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fxe8xwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id n19so314974wmc.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:fec5:: with SMTP id
 q5mr1402044wrs.245.1606162199707; Mon, 23 Nov 2020 12:09:59 -0800 (PST)
Date: Mon, 23 Nov 2020 21:08:03 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <a0f3cefbc49f34c843b664110842de4db28179d0.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 39/42] kasan, mm: reset tags when accessing metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QNShjMEw;       spf=pass
 (google.com: domain of 3fxe8xwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Fxe8XwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
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

Kernel allocator code accesses metadata for slab objects, that may lie
out-of-bounds of the object itself, or be accessed when an object is freed.
Such accesses trigger tag faults and lead to false-positive reports with
hardware tag-based KASAN.

Software KASAN modes disable instrumentation for allocator code via
KASAN_SANITIZE Makefile macro, and rely on kasan_enable/disable_current()
annotations which are used to ignore KASAN reports.

With hardware tag-based KASAN neither of those options are available, as
it doesn't use compiler instrumetation, no tag faults are ignored, and MTE
is disabled after the first one.

Instead, reset tags when accessing metadata (currently only for SLUB).

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I39f3c4d4f29299d4fbbda039bedf230db1c746fb
---
 mm/page_alloc.c  |  4 +++-
 mm/page_poison.c |  2 +-
 mm/slub.c        | 29 ++++++++++++++++-------------
 3 files changed, 20 insertions(+), 15 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 236aa4b6b2cc..f684aeef03cb 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1202,8 +1202,10 @@ static void kernel_init_free_pages(struct page *page, int numpages)
 
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
-	for (i = 0; i < numpages; i++)
+	for (i = 0; i < numpages; i++) {
+		page_kasan_tag_reset(page + i);
 		clear_highpage(page + i);
+	}
 	kasan_enable_current();
 }
 
diff --git a/mm/page_poison.c b/mm/page_poison.c
index 06ec518b2089..65cdf844c8ad 100644
--- a/mm/page_poison.c
+++ b/mm/page_poison.c
@@ -25,7 +25,7 @@ static void poison_page(struct page *page)
 
 	/* KASAN still think the page is in-use, so skip it. */
 	kasan_disable_current();
-	memset(addr, PAGE_POISON, PAGE_SIZE);
+	memset(kasan_reset_tag(addr), PAGE_POISON, PAGE_SIZE);
 	kasan_enable_current();
 	kunmap_atomic(addr);
 }
diff --git a/mm/slub.c b/mm/slub.c
index e50ddb6e842f..f23bc1feb3d1 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -250,7 +250,7 @@ static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
 {
 #ifdef CONFIG_SLAB_FREELIST_HARDENED
 	/*
-	 * When CONFIG_KASAN_SW_TAGS is enabled, ptr_addr might be tagged.
+	 * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tagged.
 	 * Normally, this doesn't cause any issues, as both set_freepointer()
 	 * and get_freepointer() are called with a pointer with the same tag.
 	 * However, there are some issues with CONFIG_SLUB_DEBUG code. For
@@ -276,6 +276,7 @@ static inline void *freelist_dereference(const struct kmem_cache *s,
 
 static inline void *get_freepointer(struct kmem_cache *s, void *object)
 {
+	object = kasan_reset_tag(object);
 	return freelist_dereference(s, object + s->offset);
 }
 
@@ -305,6 +306,7 @@ static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
 	BUG_ON(object == fp); /* naive detection of double free or corruption */
 #endif
 
+	freeptr_addr = (unsigned long)kasan_reset_tag((void *)freeptr_addr);
 	*(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
 }
 
@@ -539,8 +541,8 @@ static void print_section(char *level, char *text, u8 *addr,
 			  unsigned int length)
 {
 	metadata_access_enable();
-	print_hex_dump(level, text, DUMP_PREFIX_ADDRESS, 16, 1, addr,
-			length, 1);
+	print_hex_dump(level, kasan_reset_tag(text), DUMP_PREFIX_ADDRESS,
+			16, 1, addr, length, 1);
 	metadata_access_disable();
 }
 
@@ -571,7 +573,7 @@ static struct track *get_track(struct kmem_cache *s, void *object,
 
 	p = object + get_info_end(s);
 
-	return p + alloc;
+	return kasan_reset_tag(p + alloc);
 }
 
 static void set_track(struct kmem_cache *s, void *object,
@@ -584,7 +586,8 @@ static void set_track(struct kmem_cache *s, void *object,
 		unsigned int nr_entries;
 
 		metadata_access_enable();
-		nr_entries = stack_trace_save(p->addrs, TRACK_ADDRS_COUNT, 3);
+		nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
+					      TRACK_ADDRS_COUNT, 3);
 		metadata_access_disable();
 
 		if (nr_entries < TRACK_ADDRS_COUNT)
@@ -748,7 +751,7 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct page *page,
 
 static void init_object(struct kmem_cache *s, void *object, u8 val)
 {
-	u8 *p = object;
+	u8 *p = kasan_reset_tag(object);
 
 	if (s->flags & SLAB_RED_ZONE)
 		memset(p - s->red_left_pad, val, s->red_left_pad);
@@ -778,7 +781,7 @@ static int check_bytes_and_report(struct kmem_cache *s, struct page *page,
 	u8 *addr = page_address(page);
 
 	metadata_access_enable();
-	fault = memchr_inv(start, value, bytes);
+	fault = memchr_inv(kasan_reset_tag(start), value, bytes);
 	metadata_access_disable();
 	if (!fault)
 		return 1;
@@ -874,7 +877,7 @@ static int slab_pad_check(struct kmem_cache *s, struct page *page)
 
 	pad = end - remainder;
 	metadata_access_enable();
-	fault = memchr_inv(pad, POISON_INUSE, remainder);
+	fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
 	metadata_access_disable();
 	if (!fault)
 		return 1;
@@ -1119,7 +1122,7 @@ void setup_page_debug(struct kmem_cache *s, struct page *page, void *addr)
 		return;
 
 	metadata_access_enable();
-	memset(addr, POISON_INUSE, page_size(page));
+	memset(kasan_reset_tag(addr), POISON_INUSE, page_size(page));
 	metadata_access_disable();
 }
 
@@ -1572,10 +1575,10 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 			 * Clear the object and the metadata, but don't touch
 			 * the redzone.
 			 */
-			memset(object, 0, s->object_size);
+			memset(kasan_reset_tag(object), 0, s->object_size);
 			rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad
 							   : 0;
-			memset((char *)object + s->inuse, 0,
+			memset((char *)kasan_reset_tag(object) + s->inuse, 0,
 			       s->size - s->inuse - rsize);
 
 		}
@@ -2891,10 +2894,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 		stat(s, ALLOC_FASTPATH);
 	}
 
-	maybe_wipe_obj_freeptr(s, object);
+	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
 
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
-		memset(object, 0, s->object_size);
+		memset(kasan_reset_tag(object), 0, s->object_size);
 
 out:
 	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0f3cefbc49f34c843b664110842de4db28179d0.1606161801.git.andreyknvl%40google.com.
