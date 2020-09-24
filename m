Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJWGWT5QKGQE5MVKZYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id EC940277BFC
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:23 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id m1sf412741iln.19
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987943; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dzjg3FgxtkYZS42uPc4cshy/TLYdf+IuvUiZ2cWNGE46toS6s+FBfRpaer/q6FvloT
         C8pf7iPRBJ/l/Co9NCVVkKg8nro4P6UbR7siV9I/5/d70EUs8xqprY2vqERaqlGyO7J1
         RAdTPWdd4BsnGasKMgjQp0ypQMtzkszwkpLaW4TPjof4z9NbbjaWfEvwyFFAG+V5kIof
         Me4ADWaJ2+gffnH3kJCjvdSebQFexL9bO8ZljawxtxCHW+uM4iaV8VthQw9ejZpQmKDz
         W3t5ZOUOGUhr4VVyoe2ps7L1sc2AET0ybrU60YZUnM9DGCvbk97Nf4Zj1+4DXyKxk6ao
         QkMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=DQivhjkj1BpUtn315m0ltO85DmmwkO3uJJ2Qan+aapE=;
        b=usCgt2qM4kSDHk9TL4kJMTK6JytepkQn2oqoDrqRHQTGcUwlsRzJIxVUuhN/UmyBpb
         lt4/Rs0O6jbX4aI4rgjhvXT3yGkjU32m81jGv9OUskKq7lAnRz5c071wDZIZpWkXDPln
         Zuey9RjTNltuFQlBro+mDEF04DHpZtUUtvIXvTR8S8QeGScE+M5AGU3CpjyrrjI9uyRn
         jgA+2XK+qVXQfDGpJLA4jZnLt3rAFl9THhV7gRSiqJ6mn6QZ9vkeuGfridr0Junok/OS
         oLWLWnTHBD5Gf2RbF7h8cMUsW63+Q2aMwr+ThALTbsYT0xAXdRiUcjLVuC23QoM5LkZ3
         a+mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YtLfFJF3;
       spf=pass (google.com: domain of 3jsntxwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3JSNtXwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DQivhjkj1BpUtn315m0ltO85DmmwkO3uJJ2Qan+aapE=;
        b=dUDfF2OGrV9JdLUZyDkpDuHClloSs+lvbOK8K0ZFJVDF7K70U7W1SmDLzO1nvfUfls
         Qo6v3LmsFPuqPmb2I2o8v6V50VRDsn7w54Iua4BMB2creI3DAtJjZy/oZasrpzdOjKkJ
         DKHpp7nNID9f0T2cDCznoEnwd8Yy91SnIO3jVCEl7jKyGOKUHuQkV1m3TC1RIbufKEiK
         nO1O6uB11zI7kLw0yXEDAwi41kCFP5CbInHd8wdoxNhoeYAxSoFMA4oFVtTJhNqNz2dC
         Px9OIr6MzKNVJDvzv+pPMkvSYpSJbxs4z0t5iL2B/+YNflh7pmOT5oLfbjn5mSQTn+Xe
         KkWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DQivhjkj1BpUtn315m0ltO85DmmwkO3uJJ2Qan+aapE=;
        b=pRAWdzdDPk3BWR+YvzLjci1qC0C3BvcAVfDlSfcNjIj+2/P3A3zJaBNtKeKkE5odIH
         RPqgqDDGIhftX/VoYOs6ykvGxFcbzPeGO+p+0qW48ZOyQ3EVhEdC2vX1CXD+4qKUDfo1
         GGRIj9s59yCgxNZWukT7eASLLLgb8GHm8Imi/JAyNu1/ETs6FZt606wHXTkxsazaq4Jw
         t07pEA2OCSJUJvpG5P/yoy7ZTfZ6rFHdDNLHtCS4WGt3jqBW7/vwhlHwWnnTo2mHy2c+
         /fbDEsLAwU0IbDgpbWAZ7ilGK89lcyE/VYDWF7wig/okgrCdPt9N0T6k+mIPrQCW9IDm
         2Yew==
X-Gm-Message-State: AOAM531qlAAR82de0e9nOiePkSN3LGZytvD7hy81BFVsusTgCAXKDI49
	SQU9D276/rMBzGKT7YbVk/Y=
X-Google-Smtp-Source: ABdhPJx4Kf0IbU1UZYz/hX/GXo2qj9mb7fexfiDJ0mngLq4aBb5Fj+8ScarvquWRZS5467ePraqxUQ==
X-Received: by 2002:a92:730b:: with SMTP id o11mr768748ilc.91.1600987942956;
        Thu, 24 Sep 2020 15:52:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:dc87:: with SMTP id c7ls199420iln.2.gmail; Thu, 24 Sep
 2020 15:52:22 -0700 (PDT)
X-Received: by 2002:a92:6b04:: with SMTP id g4mr859756ilc.192.1600987942318;
        Thu, 24 Sep 2020 15:52:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987942; cv=none;
        d=google.com; s=arc-20160816;
        b=Ym7dy9vp1+0soLGzZ4uVrW/Y8QHomOjA286U3YFkzOE4591G7Yw/5z6mFF7ZVS5bfo
         rfe5LeJwS/EoeAkdikcOdTu65Au/0fbTYgJxX1++g8iLwZBPqkQ9p5B2lTY/+hlbbB/E
         mzlNPT3uDXqlFndofHCuK931xKU0Fi8ZH2krqyHvYXM7Z5HdxW654hD+TcqsxHCelr3O
         mxh8RSooZHbnOyITt6w1DCi/MESiSEJaNmv275Wso9N6H3m54gxZnVOkdtoWHWHo9pIa
         +K3Aq0hpSHYD7UWg8WAd6Z9XqoQ92PllydgBVXq/rMPFHsqEQfqY3kgXvzJkjNxgf2YP
         NAvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=95tdm8ZDV/jYg512g9xnC5FEvh1w9aO1X3WPowE8lXY=;
        b=gV8DlHRrsMm1hftyf84apvn/JLTZVxlhRRHVAeVN3PrG1pNiKSyBKvcWd33+gf9MmJ
         6SdwVV5QKknNO5GdycRsC8mAbQ+fvhWbtI1GkIExJNGqJP1NsaLANKxRiQBDhRkeSdZ5
         0se9mH7mqdLJ7K3kiFMYYthiD13uuQA0owKUgB5adTfRNp6NiJHPR0WL28cvd49zoxDG
         01R+sXVkrb/OqH1f7XOWbf9MSo5dnKAmQkMF337Y8PlGV2OTMTV00UxgZrMfz0rhXxOI
         GbVqiXmortKHAipjpqPreKxEdm9k3k6mT144REOu5Awivai0aHBEFdnB2sNhNLMazaLK
         prXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YtLfFJF3;
       spf=pass (google.com: domain of 3jsntxwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3JSNtXwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id q22si53591iob.1.2020.09.24.15.52.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jsntxwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id a14so502705qtp.15
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:22 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e892:: with SMTP id
 b18mr1654354qvo.4.1600987941729; Thu, 24 Sep 2020 15:52:21 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:44 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <a9229404628ab379bc74010125333f110771d4b6.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 37/39] kasan, slub: reset tags when accessing metadata
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
 header.i=@google.com header.s=20161025 header.b=YtLfFJF3;       spf=pass
 (google.com: domain of 3jsntxwokcsi8lbpcwiltjemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3JSNtXwoKCSI8LBPCWILTJEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--andreyknvl.bounces.google.com;
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
index 68c02b2eecd9..f5b4bef3cd6c 100644
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a9229404628ab379bc74010125333f110771d4b6.1600987622.git.andreyknvl%40google.com.
