Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZ64QD6QKGQEI3XFULI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 02DD92A2F2C
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:06:01 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id z11sf8722899pln.0
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:06:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333159; cv=pass;
        d=google.com; s=arc-20160816;
        b=HukCVe0Meju9AZ4CLheeFTrIkyM8DWEn0e/ln2BQDtdVum5GgzENr3WECUvB22egMK
         rln5WEDoOmXjiIue4bQ2hrQZI3cNvX52IBQYvx3kOQHTslNfdDGCz3z49asimIxdzoOr
         sQaOBLZRR6aqH6Rms65XAHnaTVJ1NoFTEMFCa4SCoIoeUjxmg7xJlG967YCSAR4DD1Xo
         pZdrRt5ubs8GJKPZeX1Xfhkt9dXqUT4xh8MB3wuyIEdnK9BBqx1fGQLT+iWGlJ047dpu
         1gLY/XmKT+dxWQj1ErLpoxXAde19GoLskxHE7iWah9ML+Uok1ewrr011Th02OxhAEDeX
         +RcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZSkj+ygI9nj/6n3uweE74FFsXQEuIA8sOqdibmeSZ2g=;
        b=ZWRB+CmWM7Z1zNJXEborbkH7zdLTkq+em1KzYieWKiDX8l3asHmIykKxKKmhqEj/jC
         FYVRPppXbRfipFnHkn7KKlhAJ1+VyaikRsfkEgSg7OEJjIzaIHD0r3FmPtAqke1ZnyTO
         iRUszLahzRVemCdaZYyNkull/qvkYOJfLFbVY2OKPZlGY+Xh1scsuTJ9YfO8INOEQQ8c
         AOWWIjklzWdPE2+CcCOaRI9JdTzE7461GF9uVwq7RavMvXb/DBmpjZfJeGdz2RyV5UNb
         mecjz6udtyNPjm3vIYrCGU3RUVYS0YLMpWe+D+73LTocn0znmBE/bUsVFE2tGYmKYiGl
         KGDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eK4arbIO;
       spf=pass (google.com: domain of 3zi6gxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Zi6gXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZSkj+ygI9nj/6n3uweE74FFsXQEuIA8sOqdibmeSZ2g=;
        b=WZ1v5xpybvTZ1OvrCtYCA7n2u8d1X2I6d4n0Eep1cXFtomyHqdLcgGsvyJCo1e9xEN
         ccVM0tXN2LFCg+TUopqZ7v/4zTp1WtL5yAb9u2jCXccsf7azoBlzutj52pY7MPqZwf+M
         4Zizh7Hei/baEi/0C+/7SzYg2ClpaZhtgwnCGgg9P/AcLyYGRnHGspSWWMbsTfJPvPkT
         S+jyBIZS15WlJzwkoU6smhGAdtFHjIqLbp16q2FcvZI3mEfVCxhUKQd/68SW0kixWqme
         hAykgNSnjVQ3F0sUxIKTUFFIovg9BHAisrWN91tB0AL0OHxHbP6ZTvZ8uDYJljnc5jK6
         13hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZSkj+ygI9nj/6n3uweE74FFsXQEuIA8sOqdibmeSZ2g=;
        b=AqZzVB1WAE9gwgMEHtbcrsp5RWyC3DX3OGKTOtZrQgXCuIVvfzvT1pZJvOdCg178Nt
         45P57q4n/k45fBEQEqJDcxvpsSO9rui04MOcR4yWIbiGGeYBlPNaCcoaFVZXkzFlQsLW
         llVs4Zc7i12MiIGcxPRcJRlhihu/dJDZnVxgZ9fwT1lqU1ny6XDxFDwnFrxol9Foc8dN
         tgKU+/OIWHaPWvxw7fb185GWwQMJNfIbNyYGUysLWjDsNNZYO15+wtIW0D8CjpyCXnWh
         oIarJGCNCtWJHuTVgWNXTmyjfSyz8ssq1fjocGPSe/lCY4sLc7yQ0G+PtlfPh+vVxpNL
         47YA==
X-Gm-Message-State: AOAM5332tceyJXbMYCmgwVTKXip8I9tG7SZIiWT8zQBE8xYv2Kgow0Wh
	/Nutoi9VzgDlBD7XGH1QRo8=
X-Google-Smtp-Source: ABdhPJzV5hXGP1Wn+6P9ptQel2Un0C+LrlzlGxtaNArUmp1hsHYSTp6YamtBsNr9umwk7nVEFpY1xw==
X-Received: by 2002:a17:90b:384b:: with SMTP id nl11mr8242974pjb.126.1604333159788;
        Mon, 02 Nov 2020 08:05:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7d8d:: with SMTP id y135ls5048808pfc.3.gmail; Mon, 02
 Nov 2020 08:05:59 -0800 (PST)
X-Received: by 2002:a62:5f86:0:b029:18a:ae44:afdb with SMTP id t128-20020a625f860000b029018aae44afdbmr11581286pfb.69.1604333159239;
        Mon, 02 Nov 2020 08:05:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333159; cv=none;
        d=google.com; s=arc-20160816;
        b=hcN36G6VI7xSKlvYfiJ1H89q3i5gXZOz+AdeB+LHsh20YEPhTWf/quN8VKD0tG6USg
         H7oNEHDRpRia1QE4ZqKTAw9e+jLssrRG+LLFnt1ei54iAaMByasY/YbtGL0kvInkGk8r
         1GS72A3nAN27Gz2sd4WMEH6BXmS6TCbZtxjrkPEzqkyJFQhuMdaFIwPyciMDsLgIjswL
         5S32CSeRnpxxP7Xh2zpjbbZ/XTnZ7VmDTBpTqDlXby/NV8hwSxKCwlhlCeD5jehD2Us5
         sNWPE8DehYeeZ+/2DJtzsubSekMOwtkNXw34FUB+SiA+bU0Uvce2MmRLlDEy7/Z9/XmA
         +DyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=C6Op3yFR6sxPD/1lbh7YRsoWm4fdKowdqrD7aVgHz7A=;
        b=vuU6gMVj/0L0IDFV5lLILYWhitpVscHkJgYHzEg9xF+eEq1eAbwu4IL8dlP1EJ3fCe
         Lf2IxElljdBaxGnBlyfKspJ3j8GhgwMnOtB9ptlruCxbG1hT6gZ619t5NUoKhOh+TFB/
         HkotDzYeGEGCSuOZzEXUJgdPmciEWNV+ZKl8qRWGGBNH+c/3PyIcM/FpcaUHMzIDiSKy
         IXeD9SsAU/2/54n00QbjFiwzLVbGn2cOvnNmmwSosUW/AHh+/ZCLwdgDPn0pEbLiHfM8
         kX96oWflOWoqcdu+AWIhyrkBHKVaSioxqddbL/kAUDMZr2bgcJZCKkXrh9C+MsEaA69Q
         iV/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eK4arbIO;
       spf=pass (google.com: domain of 3zi6gxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Zi6gXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id t126si1150755pgc.0.2020.11.02.08.05.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zi6gxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id o135so14533768ybc.16
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a25:d284:: with SMTP id
 j126mr21605003ybg.220.1604333158481; Mon, 02 Nov 2020 08:05:58 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:18 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <fae61a112388cfd5ee05df3bebb7b8ac10cd46c9.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 38/41] kasan, mm: reset tags when accessing metadata
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
 header.i=@google.com header.s=20161025 header.b=eK4arbIO;       spf=pass
 (google.com: domain of 3zi6gxwokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Zi6gXwoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fae61a112388cfd5ee05df3bebb7b8ac10cd46c9.1604333009.git.andreyknvl%40google.com.
