Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTWE3H5QKGQEOQEWUVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id E19CC280B27
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:12:14 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id z77sf67383lfc.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:12:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593934; cv=pass;
        d=google.com; s=arc-20160816;
        b=snCj9E7B9PduU+7L/9v6xLHnADEguhqFYWTo+A/AJ638Pn1m1G2q/ehHWp254qdkCf
         qhqV+6To5IH9/misUJCEcwt+FdOnmtfzgqNoG35n4zuzqdwpGt8ARVYiYWe/QBbqz4EH
         Yfo6c1MzSJw3nG8YJm6V2vkYlaut+F3W+R+/Hd6v8WKd8nB8Hb56n+P0Zesmnh+PYknE
         OnM2qqPgW4kxhyeIrYmPSqYnRvesCiBtAob8/3dTFAutnauj8nlSMtBhHHwwl6NosMIU
         cXI7Nlx6E8JSPdhXwyZaShu08mV3+QUTWawJp67GmiFGTQSLxevj7AXFXsh03DCUPsWb
         HWQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=46MP+TnLcBirfi5Q6QItV+eiV8n36Rf/W9nO+eags4Y=;
        b=ECm/tTA7GJ8wk3O1fpat1KmJzvHQxiOWIX3HGojE7+25aT0ySo9QGKDhAGvwhYfxiI
         NpNT8yIJIbB0r0m2Xa09sV9O62ze6F14RMep4LI7QNF8dLfNud9PYxND+XzTk2RFjrUY
         3RtBsQLw8SOJZn2u411iQQF3N078/GK+EhcwT6iDKtMY8YEl3B0FK6naVeGDn84JHvlo
         gA4cMSHUIkki9g+K+46gbLEvNLIkBovfWKtJPwexy/TXIzjxGLigpb3qfsgGVLHTdAYH
         p1jToRKG7ZaOtix1wnIGBLYNadFgHZME0rFYVm8n1KxCAqgWKvw0fSVMyJDdsft7BHbW
         TuPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TAltGYGw;
       spf=pass (google.com: domain of 3tgj2xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3TGJ2XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=46MP+TnLcBirfi5Q6QItV+eiV8n36Rf/W9nO+eags4Y=;
        b=rzCPZ+qcAmp4d0q4Di0yqwhK2wnVMr7QDHVEe6WQ7I8kId3cYDP2nueawVG+ZqMeaw
         1oCXROZ8iB9mZVhHvLCH0X1m6tlHMpLDHJRtkNS8P0e3SsHB1ssh5rO/DwdMPiE8V+4a
         v2sTIBhAgAFoRYUSuaXmY3cEOBHXFfaZjDdGmdSw4MlLin7IyjDt6TqWwwVzxv6UoX3Y
         8lPNjr6p1M4TIw3TiUqac+ZD+wRWwqoa85Y3qn8PJpCanWGQ7QOU2lmA8wcBVvODB5is
         aHQcf/byhyzWuJCPoWD2OVPZ96HF/84JCkhFw3ZMZs6+BaXgEDRM0f0UdXeiXjlb3P3e
         TEsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=46MP+TnLcBirfi5Q6QItV+eiV8n36Rf/W9nO+eags4Y=;
        b=PiEBnVCtdKzVpcVgzJ0CX9xF/4kbdrMYN1bFLCpWYGivU18LYxFbm6H0xubk+Wazb4
         knDVjWzM/yntS4XB5aIezZVwBfbCQvOu7St5KFDPTG2BmyrMDCpihmmYk7WukLJQzuIX
         iM0hFxZ6UZAS9kYLRsMCC47xWKufTCZ6CetALvuzg1l+6LRrew4OebPIJA63Eo4WWuby
         uxNZyuODm2Zm885+zNtEcty5aQ/H00dMg0JT9uNj2zAJ+qWDJdzJY36eEFezLwJUgUI/
         wzQmrOs0yPGEtiPTfHoK7I1AeSNQZt/mebOqmjTLsQVVPa58kR3YrDGGntJReiP0voIr
         p4OQ==
X-Gm-Message-State: AOAM531njIhKkbYkRDvJyuEv6CuuqMyhVcTmGVXdSju8XJ6Tv2fnf/XQ
	ZwMfdkAOjdJd9eI2x09MocE=
X-Google-Smtp-Source: ABdhPJy5ZCMrv2kUVpWMGD728v8ra6oeS0PTfXC8BfhrIimoMgGT5BqznYKktJt0NnyKoT1F/swq1w==
X-Received: by 2002:a2e:911:: with SMTP id 17mr3309455ljj.207.1601593934432;
        Thu, 01 Oct 2020 16:12:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls2145939lff.1.gmail; Thu, 01 Oct
 2020 16:12:13 -0700 (PDT)
X-Received: by 2002:ac2:5f73:: with SMTP id c19mr3790889lfc.250.1601593933539;
        Thu, 01 Oct 2020 16:12:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593933; cv=none;
        d=google.com; s=arc-20160816;
        b=f6O5A+JY7eEbHfqL4+0SMTUWP30N4KIb/MVD/AwmaXED4UkCPfr4LrmSn6aj7VAgtU
         Vb6/6K58JmcpyR2+Tyf2HBPO8QoHEIPyMarClAQjGOB1JT8YPtqgEPFIPib6C5+rdYfe
         2C3umTLRM/z3ydWKslcUY7TUo8Iq8E5avEYO2G8HAXChM+ZoxXK+5rBnuoxtEycXA1Xg
         os/iNaqu9t7D4in4i415O+aGPsvfh2iXViGe2EDKz9rJtTbU4wxLnGVNJN6SAnghGkR/
         eDPeH+IO9s8lNizNRS/Fz9n78A+PcxVC7DraB6CmMuHwYdVFAJ/ji1eLD4snIOwYZcmo
         qTNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1uiZUrDOH4l2Wn9/hfxprEz0p4Pem0sURNuAWOypjqo=;
        b=wOGqpaRsSDGh+RViT9PIZ/culdmX4mGaKPX60FYbMUI+EdVRjVrcNvy+KKqglTvOHM
         HAKsPkR0YBH8C1Qx3plmuMGRCqblxpXn6sH1ALC+T5c0U62e7sl4GYIR2ewmvPoy19dj
         DauX1w1W6FPSee66jGmJMoL1ZW34n6IUaZc5QCl0OmYjI7+nVt+nMxWBIx3h2n5hO5tT
         w3TRPWk41rQPf8zCcFry8+KBv1z3sPmi6nQaFsbOUNc6kfL1RpOHtxIGMqTQTRc++WDT
         JqfOKOtuDCIs/eb8omhkYaa9bzfXYPY8neNXuAmMOr4Fu9MSQpxQ/7A7p9ocbX+1bs+X
         z2tA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TAltGYGw;
       spf=pass (google.com: domain of 3tgj2xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3TGJ2XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id y17si207525lfg.2.2020.10.01.16.12.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:12:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tgj2xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id i10so129448wrq.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:12:13 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:204e:: with SMTP id
 p14mr2206470wmg.182.1601593932715; Thu, 01 Oct 2020 16:12:12 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:38 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <9243986ea34154dd41240ae0e0797a87c42c3106.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 37/39] kasan, mm: reset tags when accessing metadata
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
 header.i=@google.com header.s=20161025 header.b=TAltGYGw;       spf=pass
 (google.com: domain of 3tgj2xwokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3TGJ2XwoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
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
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9243986ea34154dd41240ae0e0797a87c42c3106.1601593784.git.andreyknvl%40google.com.
