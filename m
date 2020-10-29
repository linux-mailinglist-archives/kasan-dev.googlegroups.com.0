Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK5P5T6AKGQE6HVPUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id EC1AC29F514
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:27:39 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id c204sf305360wmd.5
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:27:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999659; cv=pass;
        d=google.com; s=arc-20160816;
        b=pc8O1j3k2RJ/PLz1yRm2K4EVEBzRMq+Q3NrVsbznXO9nMfVxyxEemmkL/gHOZ1n7My
         NIBuS+9atfYn/W78hwg7si/66VufCB2HmoRFcNbgRxouhY0c9A12iP4HL5uATt7SX2Su
         nCib2prYZTlkjODpKro2LgiIsaHD/FYh1j1EnsyCn32/8G7ETUPlBR1/RMa+k3STiEyY
         3e5bVej9UrZDHsLdfdRC0gpfy6Qq2B+0Q/NF/k7yQkpSIa20ebr1NHvpXLRrJ1ZpoqTU
         FCWh9TQJZdfLTZV9UpxPgNG1sTHNxUA34MmzQFBDPJclJi4wka5X8AZbkGFIqm6/aecr
         O51g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=XcKxsgviP5YsdQrA9/8xkA5m8HS+f+phlxWkmEJ9A7g=;
        b=VeUUFKT7yaJFNWvh9yFt3VwxA9TPwBqxsRm5pfdSmRfMkU5jYXjWUXAdEXi1RUbfGk
         sc0USMpiG5M68To7NMquGrR5WYyaZgMLlz23xV/3aWsY0pXOrGTI/LLK2t+W1+HXuCCl
         mZgCV1DzAcL9ag3UPYfHoBADuVYMQoH/EGcG55SqbR/YYF/Nh8VREsi7hup0fT15Q5iD
         cHtBxhptNaClVRQjUlXX1gcxsUGBh3/jpzigONDYnaMQIjrTPxMUyqlLMCwLj5yPOd4w
         MYYMrGCKTlmO9/W0iwQQSXhEbwdoFYQBRLhnX/3KqZGFBtOg45G+u+EJSsFmcNoOp4hE
         iEEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="oCrBT/7I";
       spf=pass (google.com: domain of 3qhebxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qhebXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XcKxsgviP5YsdQrA9/8xkA5m8HS+f+phlxWkmEJ9A7g=;
        b=ZUZpvT6aLDFZ9nQkXxXsiG7F/CLVZe1LCSAvfub1k70/8V4mMunb59DPiuEPsIvI8o
         J0NR4pQpvJKb2cSOxuPw6rJfqlPGEfIl59Orfw5uYiO0jRSt1M5euP03o1tPZldw36u5
         +uIb5x3tt+DsKsyqiPXWyuRGw+6zoG8o8TKHrvVEf11MeGXkzKPBV31hOm4EdJd5hXXO
         HJIiZtbWFhDrvHvEUnUaK9WCLwsWp3P4QJH7o/qD/UCMmKg6BWRhqdYiN4/AUVUB9NQG
         k97W+vKQx08vEFwFH5+QHHe3KqpZlE6Nnpguxz0LLPPRgbLsXatXlLx27OhXFcmS1ZVf
         PbJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XcKxsgviP5YsdQrA9/8xkA5m8HS+f+phlxWkmEJ9A7g=;
        b=EtDfxHfyCpMFpeJwCNroHMhYKj7Dy0q2qHkhP4vM2VTB9lq9dmTa+qhJR90MMwooL+
         5Xnf+TVxpxU8qX39PkHoqbS7bbqs/nTWugNd+4b1KHeI9yTEQ3fsH7sXYIT06Bi7g/J7
         QR0x+1p24/13Ly7u8CJJl67Th5x9mt1EY10fqqsf601LiZx8NCtJqqAfVMC0zmUhTqBB
         5kvlaRKmFh5fRv3CqMm1EzovjNJQIT573IW0ewf/DkNPbtrEOv1/m3zpHJH2Wnuk9KPj
         iFafoHAVzISWUMgcF7ROeqpnUl6dfxRrop8iZLlq4n6TiwlAJZkBjuiq4D2LpWFLhpv3
         AglA==
X-Gm-Message-State: AOAM532pSkJwlTcrw4hIGlYCEPSjp7jqzCet/qLFZ5+xWL6tG/FdvLCj
	7bXEjm8rwWEetrKUgJEg5J4=
X-Google-Smtp-Source: ABdhPJzzvLnnym9OzL1kzEPgKDnj0peIBjmy2l71cf7GhKnUB4y2hrceHMBRGS2qSOvvqfflUW3zkw==
X-Received: by 2002:adf:ec0e:: with SMTP id x14mr8262038wrn.204.1603999659707;
        Thu, 29 Oct 2020 12:27:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:208a:: with SMTP id g132ls472493wmg.1.gmail; Thu, 29 Oct
 2020 12:27:38 -0700 (PDT)
X-Received: by 2002:a7b:c113:: with SMTP id w19mr458388wmi.25.1603999658849;
        Thu, 29 Oct 2020 12:27:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999658; cv=none;
        d=google.com; s=arc-20160816;
        b=KKUBdMGnDNefh2JOPt/NHXWoARQFWEfEbkH0KQ1cakvA7fDcD+shXx4Ywu8AyAbw57
         2LqALqX7EOvTOgJQBuS7yJzTub9V73kJKUES3xE+jBhtiL3bhKKSAXEvGq66dENEU3Ik
         Txalv7LetosVAxSxMXdl3LRT7EXlSFFuZB/DY8k6tFHN+6Cx/TW0qOdpiLZQomkZTGhW
         mtf1nRD+HOJ7skfVav/d+Sl+NrTfo12NcwaRafmAfngxK325qYvl5z8FV7aa12Vqe1kn
         KcF/2xkLSvw2bvwNJyN2PLVTllwfdaMM//tsP4U0rq9TbKgJeSfaHeTgEoPgUPDzmEv/
         AKHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=C6Op3yFR6sxPD/1lbh7YRsoWm4fdKowdqrD7aVgHz7A=;
        b=0Nz2RRGGzzmi/XR+PE9ZnT/tyYnI+GrAIzLrmV04EY2cUU2PjtsYVN7cRU0c81o2Cy
         JQXi36U7ESAtRR3sEy2vv4ozfMtbY0BshcA883MnfRSfAig1FpzVy83HXNZadEbucLdr
         /1dN8PSX6nxmg5gWcnGjTz4jMPIefdUf6ACmL4LkjBXymevJPK4v4Wm8tLYC5Li6mwqj
         yEFBIqdyRaHZW3m+H7lptQdKQP8rBi9EiVc+SfiUtOhcS84AqIQmv1rEYIrkSQOMGh8B
         DUDgI0oMYEEWnO2dCTx+GtrFqVEilBae0tPpU2ILcUSPQVPzZDaeGr4CFFXgzOFdIaU7
         ze+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="oCrBT/7I";
       spf=pass (google.com: domain of 3qhebxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qhebXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 207si20443wme.0.2020.10.29.12.27.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:27:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qhebxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id z8so1563437ejw.3
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:27:38 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:1804:: with SMTP id
 v4mr5705439eje.201.1603999658422; Thu, 29 Oct 2020 12:27:38 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:58 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <41979f2984f41aba6f6a677b901c10c8731a7914.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 37/40] kasan, mm: reset tags when accessing metadata
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
 header.i=@google.com header.s=20161025 header.b="oCrBT/7I";       spf=pass
 (google.com: domain of 3qhebxwokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3qhebXwoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/41979f2984f41aba6f6a677b901c10c8731a7914.1603999489.git.andreyknvl%40google.com.
