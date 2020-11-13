Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDUMXT6QKGQEZ2F7E2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 769412B2831
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:50 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id z13sf4679656wrm.19
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305870; cv=pass;
        d=google.com; s=arc-20160816;
        b=XDpd3ArpbU+MGRy/jn8W7gxdulosDO5ydUNs8hHVPsKlJOq41Oxs/xhDYsrWG9OmbW
         75v/GhZOSP/Rmw6Jc2jeG3uwu3zebof8uy5gEHJK8szgK4h/VnrVtDbk41rSHH4ilOop
         fusN6Q4pwLwvUSmGsHDWKEBjwomhM7ZGMb0omXOxmvIHwwrXIt+5SXPQPdj3dtbkZX9p
         AbzRkrXTKh0yMhKj6fiBrx0R+4APf5upOdSiQnN/b2RDTFlR0S3eofurUbqkF57RlpAZ
         rWm8TkMDLjOGPSpxuM4yrpgec82hCsto4kGkQElFgW2kT7aKg16MjEQZwyu+eI0+gU6X
         hvRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hJ5wCh2B6PIieYIS6TYKRt2B/eyjpcnNuKVz5ynBBqM=;
        b=tpqWNFEfhoZ4pve8mMrQW28xXcKISkzPmZ2hbValzaCIigHGI1tXLyIwxdFDEQaX/H
         Rk+Otl0FwWtlfZMv7Rq5dIO7PrEgDjX0jxh/bOR8WGQyBGRQ9LoeCsMsa29BSk5kDyOU
         i1uOwhCq2bnqOQckda22XhvsnuNaNMGNnIHwApiKm+LnUGi7OXQGbSF5Qoaqtx89Qr35
         qsnGST1yeFYzEoMzZzcCHDv6HsH/OGdtfcZPCfrI6I0DyqP7J7cg7rmFlDEH82TU4pvU
         1MHNsC7hLhYAWaUCpqhyt33PcWpE1j1nqxZuMNKZ5c/wBsZ81b81t+Sw/0pw7BvTY4yZ
         5ynA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BJZUmVzJ;
       spf=pass (google.com: domain of 3daavxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DAavXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hJ5wCh2B6PIieYIS6TYKRt2B/eyjpcnNuKVz5ynBBqM=;
        b=noUIyYSf/zVbvCSEDVsgs/0xMv1OUI9iZh2B506eHSYECUoYdUKIE47vgCUXHjE7H3
         l0+gqSTPi4lVrNN2RPrJ03U+WRkv2pfHz1hnnN2+w2aeChfV3aG5U84OXQvWBtUv7mPv
         MLbsTwY7xwniAtN8DxHw6W0wKNA+76XGCfDyVJVU8gl64j5i0dPjnaAzpPfXtHm2zCmd
         cIoCyg8aC1hmYiMQwTmlLaUOFpBl72nz2UXGmHjyYhkIJ0nxTMqKENCyAiUvzfd8bgNU
         h3/HILGBNB/0Pjkkf4GcatQNnaTjg28yVT0almrO87JNREoFYlJk7Pp6th4VEDc8tHYr
         mK6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hJ5wCh2B6PIieYIS6TYKRt2B/eyjpcnNuKVz5ynBBqM=;
        b=jXefI6TQiLUYmldBrsWJvbX8hvrTCFf+x8HHeh5tXHu8ZbrMWmx3OKrj40gbKY3SK4
         4aF69ehBFspW/sK5Lkq3aA34Bhr14Ih16E1cv/QrGFIM2KYykGwZfm9XimiVFFvPX7zh
         nJp+GKrc6ZZKr0P6SL5ch3zXNKlt9UGos2LxoeB14biTjOUIsPOXyQmtPJOv8Rmd9xbA
         jkh5QQ/5yU3EsN1iGwBK8SpROTre5mahUSDtW0vzgW2OvTEnXO5+AZt8vAmOk7bbUvky
         RiAAEHI3LYFfdOeI6Wv7kvUIVo6xlV7ryazSIyfroegWkoyGj03b6+tLRCe5lbhEyCUP
         Ux/w==
X-Gm-Message-State: AOAM531+CTTVx1X2iwAjP9Ycx2hIipUpo0YgG/pDGpoW8m5UxAKqUdi7
	zZB65/n0HQy6tPmwjtNp4+w=
X-Google-Smtp-Source: ABdhPJyCuPbyWaeKzJ/tdTbvuCzUN/1GrftgP8JCxQAJ/bxd0kkVGUzvi96PGu3M8FKVo0DjIxz+Rg==
X-Received: by 2002:a1c:c343:: with SMTP id t64mr4731312wmf.140.1605305870181;
        Fri, 13 Nov 2020 14:17:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1bc1:: with SMTP id b184ls3725006wmb.1.canary-gmail;
 Fri, 13 Nov 2020 14:17:49 -0800 (PST)
X-Received: by 2002:a1c:4b18:: with SMTP id y24mr4739152wma.154.1605305869318;
        Fri, 13 Nov 2020 14:17:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305869; cv=none;
        d=google.com; s=arc-20160816;
        b=Hl6m8OIuV4BsLhujzUtwnl4g8r1XHXpn2kO/C8G7eeNbjk68vGrRT+G7D2hogZ5A9S
         iucAJgBVkPUJaZLY45C1agwo+ch0ZIvjwJE6mPOg52vrv1Buf5hgXL4sqWPHU6nAwZfJ
         IXGoMXSBN3mJFLgPhspChcjpDvzxA3GeMUg+MLT7oFAT5WjgcFX8aVnbj+kO4U3w9zut
         GwZS34g8DxgngjNpfff2kaBxmx0jj1QUWkSNzUIqfFS/7eEvzDckxnlEOQxXcPaomejM
         PItmUsdOZZ9Oo9q3Bwu5eMPOsu1spPY2jEO1NFcwvl8TezZIVLCi/v08ahiSMQEL8ILw
         E+ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Tgw0dhLMRnQraTF3rqRf/qE5jEFH9XeoJKKtJul5g6o=;
        b=YE8qvZfs2rp1cq9CyU0zRZD+jU3rf+WrpIf9nTWR0yc6qv0SpuNCSBVwB/VLg34orb
         UBn972HObKtUV740oiKkTRenboFbFPe/bzMeBg1aqoFFgvRkdQ3eavrX7e/6K1RIN5jm
         yd1S9kbIa4NcuK50bySqHvcxQ7w4AtYoWcZpx5b4RVoSUr12RAV8xFZPbbVc/8Rn8IhJ
         M9Z+tnxKfNsHymogLbQtwAwYHDlTBEw1nopiGXayitmW+jWFf0dBfV/vboPlHSj7ZeZH
         ecCZKUTHILoaNFtBB47XQsaTlLJ9FzSG0jN0oBq3LyuWmGfvNKSXUXFLSsA10UNgFLO2
         03CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BJZUmVzJ;
       spf=pass (google.com: domain of 3daavxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DAavXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v10si297834wrr.3.2020.11.13.14.17.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3daavxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u123so3999408wmu.5
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:49 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c195:: with SMTP id
 y21mr4592763wmi.138.1605305868954; Fri, 13 Nov 2020 14:17:48 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:07 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <623f0aa1265c65f4477f09f7b830fd3cd91a23a9.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 39/42] kasan, mm: reset tags when accessing metadata
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
 header.i=@google.com header.s=20161025 header.b=BJZUmVzJ;       spf=pass
 (google.com: domain of 3daavxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DAavXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
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
index 4a69fef13ac7..63d8d8b72c10 100644
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
index ccdbb62e025d..4148235ba554 100644
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
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/623f0aa1265c65f4477f09f7b830fd3cd91a23a9.1605305705.git.andreyknvl%40google.com.
