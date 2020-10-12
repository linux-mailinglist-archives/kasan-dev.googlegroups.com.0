Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHUBSP6AKGQEUZOSQOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id A4F8728C317
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:22 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id z8sf6091628lji.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535582; cv=pass;
        d=google.com; s=arc-20160816;
        b=bqDEV/tsQVmk5j9Uva17pTr04Sp2fbMLvxs2X/KtnFvIb9yT3NYmqhYUKo3xjKTcsm
         gB9IHbQHqo/l0g2PlRuppetHxAisS+GYOOqj73EwmutuhT+H5B1Ui4rzylxG1KhllqTR
         PnxF1p1qnyQqQ9kPn+kgu4RX0UUj8+fra6Zd7Tv3PnDDXyXsC30o6zKOrbdkcRm3yV57
         vP1sRD1n+SLErLvnvMqZ5JvEijMKqpKMQqBfcbWe0+/IczT41IfaywigaoeT4AoGpLo+
         wyzDDPCL7lq/4u4LLkOmXB4aLuVcM7OsG9IiWKay9vIF8/o/OvV6NC6rXg8V9Ivtpk9N
         uL/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qloaVJS6LHvO1ALmGESV+zPLWPcULiR1pzVyeBiv+X8=;
        b=xKj1pI5CuOkMYd4vkwmNlNBZOd2nJ3A5eliqNJCGIKcSHjSW4n/Kwloz2S/dMAhqKN
         SL+LmkCY8wvbcywgp1sbhh68rJmYvP/LKVQuINSClMhw/mPmVmvPnXHQBWwSiUda6VCj
         SODzU29VwpF+0NsPO7+0vcnZsVutsnsuyEpRe77ErVWRUpbLvXkJHzoJeO9qnrsz36n5
         vVK0s79CHvpqhyRBBI/TBPHetkaRtqnZu1dWjRDfvirQBHJX810lGKVlUSzCtWGkfAEL
         BNXi07SefgPc/zFD6FKU6bACccy6veUoMZks5r5vfYfBswEyj4w5erJpFKLrJSS+ZmGf
         0QPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="f/ljcHOZ";
       spf=pass (google.com: domain of 3nmcexwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3nMCEXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qloaVJS6LHvO1ALmGESV+zPLWPcULiR1pzVyeBiv+X8=;
        b=p/liUJzgyl2VQZsEyN3hC2cRN/G4nPGgiazx+fUpSZeQQ8VWQkfEYjmcJEKduZSiIv
         5vAmwY8CiYp1gIeRGm2GQfyrZPGwe+DVcNePEbORdZIWu/JT/nD+4bBJftd6nwA/+11b
         1PTIqp3q/QZs68j6Sf4alksVzIFc5jdZdLLQsm67+ZlzaVdGOo8nH3ZMNhIROB9mdK57
         mIGySRA8wKHC54vrBzR2/HxbpPiMR/SRnj2OsC3Zvx2++yQ5KpAPrZZTfPJccrTtHuHM
         O+ZggCvgjEL9vCADp8ouuJw10tZcw6Bgk3sklb0hVvKMmJZUibgtv9YWhqaQESMKkgsf
         raIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qloaVJS6LHvO1ALmGESV+zPLWPcULiR1pzVyeBiv+X8=;
        b=sqMNyqXHGJFgix2ii8tJNgkzNGc/obtJYkca+kTJE8oVIhgl+M9JKDJmhsgYp7Vkcz
         WKAKnIdwZBlbYEKbzwPO+RBQRNXElXnXxqXFeya4SwbvHf2khmtzB39gaKJFiPteBIPp
         0QBydbbd6yHaV4mTv89TqHU0tpJgRsUVWLKU8QinELXUKjz44wACks+VTHQPUX+psK+m
         LEBy4uZcdRZkLPr1t6rVNg+/XZyG+kwQ59efjj65S4qUAw/Ay44JL4k6+6Tf+WmnbKwC
         IT6jE7UQFbXvz7TVrrY4w2qYo0BqROTVIkniQEw75DQB9aJkW3WisAsxHe140Ukn8maX
         JL9Q==
X-Gm-Message-State: AOAM5315SbJKali3tZZQmPSrnz+poDRERLbul9FvGU/JVRbUkpzylMNj
	YpkmI+HhxvCt3H/s0wDGzlI=
X-Google-Smtp-Source: ABdhPJxl1KL4j9h79nDOVDWmUqR+3RiKUdK/y1+gRu22c6KYpD738W2CFDx6p1k7cotqZbng+9IC1w==
X-Received: by 2002:a19:8296:: with SMTP id e144mr9084740lfd.463.1602535582205;
        Mon, 12 Oct 2020 13:46:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls832930lff.1.gmail; Mon, 12 Oct
 2020 13:46:21 -0700 (PDT)
X-Received: by 2002:a19:cc4e:: with SMTP id c75mr9384171lfg.364.1602535581334;
        Mon, 12 Oct 2020 13:46:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535581; cv=none;
        d=google.com; s=arc-20160816;
        b=cFPF4wJCI5UjzrWYEFHVnEpAHsMSYFxW/WxlD0F1dmYMQok+C4mrZjeIqFoL3jZk8u
         3NBNmK1OjKtkOvb9xGsVM0MNyy8JPwOFkPdNxvLnOBPJTrJMdTP2sfKloXhv4dlTiWq7
         QpZMG1nPXfh6PwLLBBZ5xPAy1dg+KQllvaik+SQUK+xucinBRSUo/zsmOPpLS0H4WyTE
         0TY5g5r4UkNvw3HwoRoGmQjvEadcQA2skQLE399uWPSxI4SpDKAZ0Y69M+3a2OJRirix
         PA47wQnDeAmAa+2LaQClZynJqHoF5dHwp16y1aYjsJAs7rZO1FT7uKPTB85qY9q3Igs0
         oMRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DXD/bC1uAj/kWrmm4oJ9WqE5I8XLSwAUdCmOAmSltBo=;
        b=leoPlQZmjj9QhNdlH0KALYSj+SifImnNdKWGpMQDbrPTQiBQwkCl1cGXxE4prAyKgL
         9uuNHLzY4HDtWW07SEW9GgNZia9Xb5c4YX8HKVAoZAH59q8M9y/oWscA0bIRxWsmgLvF
         83f3r5qZUNMv7yQg0tlLm+1uNEm1iZjHaW0rzpqftyGjUYkZzGnUDuhgigVbNRrqDTKO
         w008si/GO4DSgs7fpc+wHPYh0tM93ko3I8jgv/2LXtaRZOgIN3EePtmU3625FcxR+PGj
         7alTFRcJQPNF6yntz1fR5Ndd2DmjC0y7YiVnSX+rehTxkd806ujjvhiQ/xS14ujb45TE
         qZNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="f/ljcHOZ";
       spf=pass (google.com: domain of 3nmcexwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3nMCEXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id i16si162792ljj.3.2020.10.12.13.46.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nmcexwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b11so5999898wrm.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:21 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2d8f:: with SMTP id
 t137mr2158011wmt.26.1602535580897; Mon, 12 Oct 2020 13:46:20 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:43 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <bb2c437e3fb6e88cb58cb4532a9faff59a507101.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 37/40] kasan, mm: reset tags when accessing metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="f/ljcHOZ";       spf=pass
 (google.com: domain of 3nmcexwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3nMCEXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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
index fab5e97dc9ca..e2195602fb38 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1159,8 +1159,10 @@ static void kernel_init_free_pages(struct page *page, int numpages)
 
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
index 68c02b2eecd9..1d3f2355df3b 100644
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
 
@@ -1570,10 +1573,10 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bb2c437e3fb6e88cb58cb4532a9faff59a507101.1602535397.git.andreyknvl%40google.com.
