Return-Path: <kasan-dev+bncBDX4HWEMTEBRBS7ORT6QKGQE2YM47NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C2222A7151
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:44 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id l16sf11170wmh.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532044; cv=pass;
        d=google.com; s=arc-20160816;
        b=cf6y16uPTntZbXhRAIFWs/SKSoQB8z99qge9H1DG+E4KHh/IMD1dbCFjF12tOlUKEC
         4qovo1+Q5lxkF74xCe9s7F6QcjNoMoJXoxjxjSXuuFrftZm5C6Jr9A7r6+ErSEJDkw0K
         es+XmOaP4vmXEMhORskIJkyhEIJGpkRVnShsrblyeHaZLRdHHlStjvUW1lwQ0ZqoOW9r
         mCusoLXvkGq3vL3vM+umMiGxo26WnTOon+dBwOJXEJH+8mMLQeUks1lh07/dLk+d1Kt8
         76A/TbQn8CRlDWp+gu33AosDsaQjiGrli8pyUFTARXUOsN+R4J+gjlHBlS24FxaDJNwk
         90BA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ECcJMdGcx65UJCmW/jRRRyNrOfkNMTMVj1WWTVv05T0=;
        b=x4MeRZUE51OAcj9N5A6j+tBgxBWIS9Vb8mX/7NRAYbtxvb+ja4zidT9V7rAQSXvABi
         NPaZ9yiEdpsitCrCCOsaxCjC/TWXMs+uItMnAu7sbYhoVV/l/IX0vjykwjTcowZSS/g7
         Y8w6v/DXwWxP/PZBHQ+W2zkSzvjep6AaqAqi/PRS3MYWHQ3UE8GLR400UI0PpGmZ/ZOW
         XjMNs07TJKX20yZfsCfwBLf9gMeX2MWkrEW1zb8lubgzuIUGrgMwhb8chgWTYk1Piw9f
         f2iZ9LaTIaJ/4fXEMPJCdB7uE41CkXdmJRaNOLLS9uL/ABotv7kDt8Ohj+AVZkvPR3Sr
         2Vpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=urLNJdGS;
       spf=pass (google.com: domain of 3sjejxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SjejXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ECcJMdGcx65UJCmW/jRRRyNrOfkNMTMVj1WWTVv05T0=;
        b=dXRaJKi842lsQv7uY3A1LQC2xBAiE9uAP4VxCRsGdaDp09cTQkMrqRGbMvnvw2Y5aX
         lXkSGS9PzIV2Jht8YpKr8fkGLg1LOc6tF/kRLfur02kXrMo1boQwv/I89gFMtLq6zs3q
         uy+P7h1PNo2K0zIa2hIWojklaLYf0qlwG6S7QaYp3yoj4DdfzEtrLBn1d4wLUD+3aUhJ
         5nNe3TSJ7dJXKICC2dkP4A4OGm4qd3f/qBQ3f2hM+jx0QRKppCbmalSq+bn/11ubUTQ8
         rX9UYQ7iphiBwmApnSqDkmr31e/XPL+vYiKSRDBev8ci3Mu55+D5wF3/a8TUIZV257dT
         snfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ECcJMdGcx65UJCmW/jRRRyNrOfkNMTMVj1WWTVv05T0=;
        b=RgohTO+I6gn1SBVUXn0IDYSuHifeTG6fm/rH5A38qq1MjGuYGLNoHyvpqIWYSH5nQr
         Jxx5O68wOBp4dhDyairBjdMya3ei2V0RrPA9JvusNbBkZ2EslZxjTUdyKKednHm9D6mL
         61b+iyWlhwUnV2DSc+0vS7qLl53v9jo1Y25r7NkQlKg2MC3LLA0TYXVcuWF+t3HtYPMx
         o/A5LxyYYzGEZrw77i/V93kS3MCrKfrwZ1JCBCJMAf8Jey4fUhu9ijl0KnKiC+2zYJqN
         BkXnQdPjEsu5bzSVunXuNhvxPPVDvv2OqSlULuogSeTx4vLIx6eFGLSPqaGuMnZsVBXb
         XYMQ==
X-Gm-Message-State: AOAM53339QOm68hH6eGq9rvU1jZ50su/GlwEXlhLZRejf+UrMlw+eQtJ
	L0e3jkVzIYfhgegOsQxzXX4=
X-Google-Smtp-Source: ABdhPJxB5ee8wp6+M1NaWdEMya6NqXDceL3NUkpzeHjEruvewUUlLmXXFfiDgUOa2N+rBymFADr7gQ==
X-Received: by 2002:a5d:4e8f:: with SMTP id e15mr394047wru.390.1604532044139;
        Wed, 04 Nov 2020 15:20:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2348:: with SMTP id j69ls1890290wmj.0.gmail; Wed, 04 Nov
 2020 15:20:43 -0800 (PST)
X-Received: by 2002:a1c:a98c:: with SMTP id s134mr53136wme.159.1604532043344;
        Wed, 04 Nov 2020 15:20:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532043; cv=none;
        d=google.com; s=arc-20160816;
        b=gaGyU5NFdfAF1udO0FjIV7b/1hUvLViUzEJdlo9wBd+xU8NCUuWKiG2JAnG01gWre8
         WT+2nEB2w0PT7MOy7B40+FYSplyW4GsbJiZYnQmJoZGRfZNND2Vp0FMHHxXJK/EdIejG
         pvHyCPBXRtUOiAg7ZX4KS2hgW2Ae9bE7fCDZRc1k600TAUsk0boZZ6VSwAfFjcNeo7RU
         3JAR8cmBWvSvoe8Val6huhD0evWm1S7o38vxNnrC2qNqWgzI72Y5Jzq7FffjY+GBO1yo
         WyjDeDjDHE4gMnydapxw60emtRFbumdpEFT/i0JHYBshHEHbfWwSyCYNlephrLVGMa0S
         U3dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=C6Op3yFR6sxPD/1lbh7YRsoWm4fdKowdqrD7aVgHz7A=;
        b=L74sYWeTtKYxyZ+02LXU5hXazxAaW5hFVzPWc+uM0MAk7bDy3VfOJW3mgXrSTjhh14
         /DYXM3n1hdYMfZLtXAk/jBWaI5kFzCAAT9IQPNO8hOmJt299LrulBVbr3Dgr40o2+U+x
         OCgYXH1hr6sp8ShLOWA0nePIxGYsr59zzVn0fvPfc1lbkIL/fjd0U7wBbNRjup+DJz/f
         Q7xN5jdzPBnOkEpUm1seD1zfMWVaxP+fOAclqDPzu9He+0KITdz7K8SWp77uPFKE1TCp
         SYQ6HHg7QzZ1kZ5ey5frULBJvblTWzbag9YuoOHnH6WIduBS2xLHAy9vT9QkMeNcyf/9
         mDfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=urLNJdGS;
       spf=pass (google.com: domain of 3sjejxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SjejXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f131si105913wme.1.2020.11.04.15.20.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sjejxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id t14so51281wrs.2
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:43 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:2487:: with SMTP id
 k129mr97091wmk.86.1604532042965; Wed, 04 Nov 2020 15:20:42 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:55 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <578dd0990cc6a02fd47d2d0a442db1c628fef91e.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 40/43] kasan, mm: reset tags when accessing metadata
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
 header.i=@google.com header.s=20161025 header.b=urLNJdGS;       spf=pass
 (google.com: domain of 3sjejxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SjejXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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
index 23f5066bd4a5..6231a6e456cf 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/578dd0990cc6a02fd47d2d0a442db1c628fef91e.1604531793.git.andreyknvl%40google.com.
