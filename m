Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXVAVT6QKGQEWNZZXNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 423782AE2E8
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:47 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id i3sf5273164lja.15
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046366; cv=pass;
        d=google.com; s=arc-20160816;
        b=OpVKRDM/jPM7K6dNx59ifp798YaAUw5EGrZJuEGe+z92g46PAHQ+zb7sKWxWHFaaVG
         Pj3JqvO5vLXMn/5LB3AjHxVn3ha/d0KhjhRB5iaoNvw8atq9Krpb26o3ZapjE7s94V+Q
         qvHn+UC6wyT9qYeqtLN3gZpJeFQ9+KjEcTbqM93uuTpwdcmdThJ8Hqy1vtqkAIYUQCRe
         QuY2BsVnIzyYrBO8b+ujdCiHBmpvwV7fBBoyaUD88xu9DCkXWkdtMTs09zmJQwQnIe1Q
         3UNFd2wN9+b8bLgbejeFLs7FkLkm40jAMwsjwMpmOWk6VLFl5eK716w01mHaVJGK9wMK
         +uxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=I9qmMd0nvLmCG9SCAMxD9/zQTV6xdyk89M38N+N2hLQ=;
        b=zY2tRMc/J1lrlDLDfOLv9t9D4wZrvIWcKy5PbVubwXXmzYMSOZQ/GTDCSP+AF34SSS
         Q7c2SzydAx9uS2i9Ig2dQqzKvL/uX9S+gw/YA2QNFr3sp0HFa2mPuvNHg0zJBcn7QG9p
         zd5Hr4c0ldf1s+sDIw/jrO//THPWs44IDGzpmX/v6yAFnKfmxH7ehWAOiu2L688l01aK
         J8EeKl/Wq1eSf2ib8vXd7FagyDCfmfMUO4L97EndfcRzcTCWUqPYbUhjb1ANYEtWihVM
         HEQaNUJITVsSID3cIzNcIYK4mRrKa1KW237Tv/BctHiMl22DFEEuj4OyCrD7hxsRAbpE
         +MGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UWk6LAWe;
       spf=pass (google.com: domain of 3xrcrxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XRCrXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I9qmMd0nvLmCG9SCAMxD9/zQTV6xdyk89M38N+N2hLQ=;
        b=gPtcLFIaNefj19gX/U3PWPh6txM8AM3EXlPOciSIEICGHStV6KVwcbXuLwBfVsFTuw
         guT/a7D7vQ0PKFmaIODvOqoxEzHU60asbPquKSeTs92HU23hcTipqTjjWgKAdBUJZjS1
         h5Cd+NjyRi0CnUDYXXwBCpdZrauAv4hUCWAowQh2mWbXRuLHaiwhgF75+VeFYcVCdlyw
         tvTiwFVN8iBBc8LgYlJ+UOyOAU4DUs+SoRUhLtwBGwu2sRJ5yQwclNVlk5BABlGVw20+
         DOIRlLzpNH6bt7/U6CQKM6ESm05BNw/9R2DFwg8A6fikNLihhBM1l/SFxHFV6rizceDk
         8ZBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I9qmMd0nvLmCG9SCAMxD9/zQTV6xdyk89M38N+N2hLQ=;
        b=eMsd2NSO/0deBMN9Dhlufk0lVHHxFWAsNOgNx+/qYAazzQTL7jJo+ywwRFJMcBGfts
         /WokFHyfB3ruL5P0CtQ8oh1kmqPUGSB9SYcvVGYFIzh8zNX26yjhKLPUi0vdPtzRVJ9i
         98ceA5KnoiaY/Em6dmsw9Hz+PDpqzxULPn/OeZvD5dNmoX5XQjcFJWF36hXsCj5HzrU5
         gYrKaSGrNeU9ZnemhPDe3FW6AcTXOKwPMcHeYq/ATUm+MZm9fwWbjNRciH2M19XpYCYq
         ymVsSNE8NjS9XWR3vrTdKoY8CAIJy+yBJW/x04wCDfF59Nm4uARMRLf47YbxpPVdgDTq
         tpZA==
X-Gm-Message-State: AOAM5304WAyMmfKz7yCCltxTz9vXyoM5GLj33VkkLcrH7Q8Oxo6TRVe1
	VUqOwXxnmBKfgT9A4hklvbw=
X-Google-Smtp-Source: ABdhPJwygozsczDsOuIY3GCPM6e8qPwz+EgZ1wC+M7bGgT0EuU43vwroTn5LFGOvSjNhF48WtGsxdg==
X-Received: by 2002:a05:6512:6d:: with SMTP id i13mr5320968lfo.491.1605046366745;
        Tue, 10 Nov 2020 14:12:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls1285711lfa.1.gmail; Tue, 10 Nov
 2020 14:12:45 -0800 (PST)
X-Received: by 2002:a19:4257:: with SMTP id p84mr2509265lfa.556.1605046365721;
        Tue, 10 Nov 2020 14:12:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046365; cv=none;
        d=google.com; s=arc-20160816;
        b=LZlQWClEBBrMt74zPvr/AwMNm3DeFMjvgU7kJ0GuEdsaOyK8DR7fPjWSZIEBAbG0aN
         td0BqlQA7GcmjApJ7BvjJydoCYJ9qPshtZIzcpewnHdgfNkIMwrxb7pac4Juyq3kYxLR
         1iJlAjTx0qe1Nu5r9YbIz9oCthAv4X2+lzHKShkPCHk1Tcwg53XNrzEK9q9tGNc8tSRJ
         9/mCwu2TEgFFRZirjCiyajLuLHsFbgJus0DG0cbsEdskhOyXjns2UvR5opH77FedGMCr
         oaB4TJhkbhfCJIGivMekn0rsorOEhS9ibUa2AHWy6LkHeOMWPHISN9EgPJlStIXkG3yd
         4AuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=0igi5mwDUPYOEUY4z2Y7rTzwQQPhibQBSH9sfTyI6b4=;
        b=nU8f3vEA2u4tXn+E1VSKk5RsnGpFsGCqkMmvdejQMpHF2uPCIFYtp2bYD2irKMddmA
         0EivPZw38ayAyPntPN4ByqyMDCCmOtbX4sA+L5EDFKiHK9Je2xNa4CvqJo77boIghPx6
         7ANkRL0nAXtdP3mAly5s/eZt79wbCBpsyGR0stK37JV1xcfyvnPRDa9MurY6sJeOpvYf
         gHGTFu9nuzlMVmp8kWsnFrC8jkpUnbsO0MDmEBhJm8AY6NvYl61X2JBaWcgedZfFFmJr
         FjW6x8ioaL02CfMrSunS5/FjRyKx8x14mC4HiSVlqQdk7ZRaerWrpn+XcEf4zM/P+JWO
         XRGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UWk6LAWe;
       spf=pass (google.com: domain of 3xrcrxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XRCrXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id y84si3884lfa.6.2020.11.10.14.12.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xrcrxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u207so1858386wmu.4
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:8095:: with SMTP id
 b143mr230260wmd.147.1605046365189; Tue, 10 Nov 2020 14:12:45 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:38 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <d0060171a76ace31b26fef1f2713da209099fb99.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 41/44] kasan, mm: reset tags when accessing metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UWk6LAWe;       spf=pass
 (google.com: domain of 3xrcrxwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3XRCrXwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I39f3c4d4f29299d4fbbda039bedf230db1c746fb
---
 mm/page_alloc.c  |  4 +++-
 mm/page_poison.c |  2 +-
 mm/slub.c        | 29 ++++++++++++++++-------------
 3 files changed, 20 insertions(+), 15 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 24b45261e2bd..f1648aee8d88 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1195,8 +1195,10 @@ static void kernel_init_free_pages(struct page *page, int numpages)
 
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
index ae0482cded87..e6c994af7518 100644
--- a/mm/page_poison.c
+++ b/mm/page_poison.c
@@ -53,7 +53,7 @@ static void poison_page(struct page *page)
 
 	/* KASAN still think the page is in-use, so skip it. */
 	kasan_disable_current();
-	memset(addr, PAGE_POISON, PAGE_SIZE);
+	memset(kasan_reset_tag(addr), PAGE_POISON, PAGE_SIZE);
 	kasan_enable_current();
 	kunmap_atomic(addr);
 }
diff --git a/mm/slub.c b/mm/slub.c
index b30be2385d1c..df2fd5b57df1 100644
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
+					      TRACK_ADDRS_COUNT, 3);
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
 
@@ -1566,10 +1569,10 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
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
@@ -2883,10 +2886,10 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 		stat(s, ALLOC_FASTPATH);
 	}
 
-	maybe_wipe_obj_freeptr(s, object);
+	maybe_wipe_obj_freeptr(s, kasan_reset_tag(object));
 
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
-		memset(object, 0, s->object_size);
+		memset(kasan_reset_tag(object), 0, s->object_size);
 
 	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
 
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d0060171a76ace31b26fef1f2713da209099fb99.1605046192.git.andreyknvl%40google.com.
