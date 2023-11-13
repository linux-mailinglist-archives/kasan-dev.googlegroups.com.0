Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCPLZGVAMGQEOXXMUXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id E6D307EA371
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:18 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2c562dab105sf31797791fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902858; cv=pass;
        d=google.com; s=arc-20160816;
        b=uioZNSAhqtccHjmLg/Vq6xIBENdK2qTWJ2ogQWFLSzyshrlDSRJCu6m6gpZQe5K+Ol
         jTP89a6OpiBYhP+yJt68vJUJOoqy8BX8cfYcoU/W0TUcphnNgziWGzL0ETfHnRGSKY1T
         4tS4c2pHdHg9gjCMlRzHRnuDXJpwfy7z2Vu05KbhJNF895vX1aTEXRFakTDQ9xAsvy3v
         hqT5NdHhuOCxoYSDMYxdrEBZ+4FG0LV9gwRdNLBRxQzytZlSPX72W1qaqtCtjXtjDLW5
         pEZPxJfrgjJJrsbEGpz9vXaZrxVE6GJGIGF36HdWQ08H+9NpyAWO2Cp+u54+5MUHz2BD
         2Kqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OO1vlemQGu1VBkWhqWG+MCfbkmdaRccahGftZyzpn9o=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=HHGruQ6LxOLXjW1Mu77hkhhO+npV5u6iaER9i5xQ00809a8a4axO5uDO95pUHsEyHW
         VLz83GV5FXVWLR5ylTC1wkRaNJrDAb0RmZMUcs9gNJl2/K6PEcj7CaOa8t2GPAbqGmXd
         YzoUaFpkUQSDGry3WeZVhF4tHgymYsv1pMBv7HVnFX72Cwc22WUJJ1pOiy8FRW6v+4wA
         VgrD28CkZJOtB66ET9ZdG4CWSBIWqyeX0QwzH++2tRXZGoBd5RAItMh5yZKTcKVL3G9H
         ZLQztMVIwswAPBSP3IUVpXvFrXKjqC4hhlQtRu1xOa2Bj+zRf/j8qONaA3NYMaOlNx7P
         SSLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=D46Whj8Q;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=Sib4jhJi;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902858; x=1700507658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OO1vlemQGu1VBkWhqWG+MCfbkmdaRccahGftZyzpn9o=;
        b=hOTR8yK7AP8iOryBtryoux3y20IvWN6Olty2oUnaXAZLO+ZyIzWa4eih7wr+qncFqr
         SxzCnLkQzX/65BrY+4Bpq1EXYulSnuXNM+qPpyHcglRsRrEYufRClHK/2yibbSgl5lGq
         g+ePjt1oE+ckfL2MxUgEZGc/40CBvlrckqh5BOpB3Vj6+GhOyKlVKknQu/h67AC9ljQ3
         HtnTc6TqnNUWiEfmdBGnYX1/NpXEkWYxvF4cW7O/6LjWjaAbp/3iq0gldG7dULXl1l5y
         iWDzbPOBJE676nIWa0mEyzXcrSSSwRaGuGWVjfpY92fuydtRPSMDiEjDkIfubVkiJJzD
         HMtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902858; x=1700507658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OO1vlemQGu1VBkWhqWG+MCfbkmdaRccahGftZyzpn9o=;
        b=aPXIzhV2A470m83W3p0ZXojO32ky4BAfNjM7c2WuTbz0tZD6HzQMMlXLvPfcG3K0zU
         K4PBno44k//4Tc7f4F7eARWUZmL4Oc4MH3PmSR067KmmuLDdm3DnwiWETwJGYnColgSU
         NSQ0uinZhl/XmRTwVLR2jPXOGWi4Mzr2gq9YKMcN5AOhLgbTz0dAE6aQQhWLsQq+AzrN
         26kwFyNb3XiqezMZZkwUDfdmZwZbxDL64iKm1BnMFCtg2L1+CAKhoNwT4ME1NNUBF6z8
         dmkSaeQ4uyWcat/oMdPRcLVJkEzTzyhge4y+3SFnJiqNGMHvJ0D7HK6B1CmONDed8knC
         d+lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwvwA5nc+/0csCngHG278gQphSsaI0hGJPEnxxC1o4lvCcQRMfN
	5RjFqF6GIHKtnd4y4sEJzo4=
X-Google-Smtp-Source: AGHT+IHVJbo/qbHqajCCS+Hs2KNL+j0CaLgXNA7RatBzHPfK0MnDyYZZLXOLhBUG2eH5OeWhZZsgBg==
X-Received: by 2002:a05:6512:78e:b0:509:b65:6cf0 with SMTP id x14-20020a056512078e00b005090b656cf0mr125800lfr.33.1699902857604;
        Mon, 13 Nov 2023 11:14:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:159e:b0:4ff:9bbc:f4b6 with SMTP id
 bp30-20020a056512159e00b004ff9bbcf4b6ls867471lfb.2.-pod-prod-00-eu; Mon, 13
 Nov 2023 11:14:16 -0800 (PST)
X-Received: by 2002:a05:6512:b0a:b0:509:d0c2:66db with SMTP id w10-20020a0565120b0a00b00509d0c266dbmr183440lfu.4.1699902855734;
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902855; cv=none;
        d=google.com; s=arc-20160816;
        b=1IwzAz4buC5cJXCO5jDvUn5Af7Wq6qHSLwcqSqK0Axi1V7WTDvu3YQFUYO5LUrf399
         Gt65Cyk01srCxJVcvDFoxWZa2t92BMV5YOdNxAnJRC9b1jFjp9Ili5gAJ9Uljo1dXRdx
         swKjjeHIvfuZ/n71U8nULiYn3TK1kt7Rkvi/fnrT5qnu5EFiQTsX5NcdTVV+ej0BzDHe
         /rGpgJ5LRTMWko/ANRce0cmLr0lHPvDQpzWJmXfL+t9B/ehqUeceKJkTaJgrIZlr2g/v
         IuLBCut26IH56UDK3iLWbZLhoyM2wl7M4clDb8XH1qpKMw80FCZ4d8sqsJsmHpI6O70r
         t5kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=C7E+/AO4YI9JRw9v06Xn3hJRV/04TmJk0Y92H5grHWg=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=rGbi9j+DRuvZrR/Sf2YW4haymu1jb7QtD33Po2FWEx2KPDlw15DpcQ9+/OrQTPMgB8
         ODpbGMfrv/CODHel/Kn6bRasr0O+fCDvGWGRZ6tfp1VQ0JXTva9PYrJd1fKAU5V7QFN7
         WrHtJU7N9uiickIKFX0qJr2M1nOH4D43O9dETV1I5nG1ApjXQcVZDWqFjGuxB0Lwpl4D
         aZ7LkmMheEmPJi/i5nxMR/0StgWx5lg1JpyAXDLDdljAX3UGkfvk7982QaR7Twyls3MG
         xULYisDICu07AFniROj8xQNIbDA9c2gFPR0NVdCGuDd3OZIsWjX9yke7J+qRvOrwZvBi
         oKtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=D46Whj8Q;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=Sib4jhJi;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id bp29-20020a056512159d00b005090fd18c05si232091lfb.11.2023.11.13.11.14.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4048A2192D;
	Mon, 13 Nov 2023 19:14:15 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E469513907;
	Mon, 13 Nov 2023 19:14:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id GA4qN4Z1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:14 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 17/20] mm/slab: move kmalloc() functions from slab_common.c to slub.c
Date: Mon, 13 Nov 2023 20:13:58 +0100
Message-ID: <20231113191340.17482-39-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=D46Whj8Q;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=Sib4jhJi;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

This will eliminate a call between compilation units through
__kmem_cache_alloc_node() and allow better inlining of the allocation
fast path.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h        |   3 --
 mm/slab_common.c | 119 --------------------------------------------
 mm/slub.c        | 126 ++++++++++++++++++++++++++++++++++++++++++++---
 3 files changed, 118 insertions(+), 130 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 744384efa7be..eb04c8a5dbd1 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -415,9 +415,6 @@ kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
 	return kmalloc_caches[kmalloc_type(flags, caller)][index];
 }
 
-void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
-			      int node, size_t orig_size,
-			      unsigned long caller);
 gfp_t kmalloc_fix_flags(gfp_t flags);
 
 /* Functions provided by the slab allocators */
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 31ade17a7ad9..238293b1dbe1 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -936,50 +936,6 @@ void __init create_kmalloc_caches(slab_flags_t flags)
 	slab_state = UP;
 }
 
-static void *__kmalloc_large_node(size_t size, gfp_t flags, int node);
-static __always_inline
-void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller)
-{
-	struct kmem_cache *s;
-	void *ret;
-
-	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
-		ret = __kmalloc_large_node(size, flags, node);
-		trace_kmalloc(caller, ret, size,
-			      PAGE_SIZE << get_order(size), flags, node);
-		return ret;
-	}
-
-	if (unlikely(!size))
-		return ZERO_SIZE_PTR;
-
-	s = kmalloc_slab(size, flags, caller);
-
-	ret = __kmem_cache_alloc_node(s, flags, node, size, caller);
-	ret = kasan_kmalloc(s, ret, size, flags);
-	trace_kmalloc(caller, ret, size, s->size, flags, node);
-	return ret;
-}
-
-void *__kmalloc_node(size_t size, gfp_t flags, int node)
-{
-	return __do_kmalloc_node(size, flags, node, _RET_IP_);
-}
-EXPORT_SYMBOL(__kmalloc_node);
-
-void *__kmalloc(size_t size, gfp_t flags)
-{
-	return __do_kmalloc_node(size, flags, NUMA_NO_NODE, _RET_IP_);
-}
-EXPORT_SYMBOL(__kmalloc);
-
-void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
-				  int node, unsigned long caller)
-{
-	return __do_kmalloc_node(size, flags, node, caller);
-}
-EXPORT_SYMBOL(__kmalloc_node_track_caller);
-
 /**
  * __ksize -- Report full size of underlying allocation
  * @object: pointer to the object
@@ -1016,30 +972,6 @@ size_t __ksize(const void *object)
 	return slab_ksize(folio_slab(folio)->slab_cache);
 }
 
-void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
-{
-	void *ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
-					    size, _RET_IP_);
-
-	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
-
-	ret = kasan_kmalloc(s, ret, size, gfpflags);
-	return ret;
-}
-EXPORT_SYMBOL(kmalloc_trace);
-
-void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
-			 int node, size_t size)
-{
-	void *ret = __kmem_cache_alloc_node(s, gfpflags, node, size, _RET_IP_);
-
-	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, node);
-
-	ret = kasan_kmalloc(s, ret, size, gfpflags);
-	return ret;
-}
-EXPORT_SYMBOL(kmalloc_node_trace);
-
 gfp_t kmalloc_fix_flags(gfp_t flags)
 {
 	gfp_t invalid_mask = flags & GFP_SLAB_BUG_MASK;
@@ -1052,57 +984,6 @@ gfp_t kmalloc_fix_flags(gfp_t flags)
 	return flags;
 }
 
-/*
- * To avoid unnecessary overhead, we pass through large allocation requests
- * directly to the page allocator. We use __GFP_COMP, because we will need to
- * know the allocation order to free the pages properly in kfree.
- */
-
-static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
-{
-	struct page *page;
-	void *ptr = NULL;
-	unsigned int order = get_order(size);
-
-	if (unlikely(flags & GFP_SLAB_BUG_MASK))
-		flags = kmalloc_fix_flags(flags);
-
-	flags |= __GFP_COMP;
-	page = alloc_pages_node(node, flags, order);
-	if (page) {
-		ptr = page_address(page);
-		mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
-				      PAGE_SIZE << order);
-	}
-
-	ptr = kasan_kmalloc_large(ptr, size, flags);
-	/* As ptr might get tagged, call kmemleak hook after KASAN. */
-	kmemleak_alloc(ptr, size, 1, flags);
-	kmsan_kmalloc_large(ptr, size, flags);
-
-	return ptr;
-}
-
-void *kmalloc_large(size_t size, gfp_t flags)
-{
-	void *ret = __kmalloc_large_node(size, flags, NUMA_NO_NODE);
-
-	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
-		      flags, NUMA_NO_NODE);
-	return ret;
-}
-EXPORT_SYMBOL(kmalloc_large);
-
-void *kmalloc_large_node(size_t size, gfp_t flags, int node)
-{
-	void *ret = __kmalloc_large_node(size, flags, node);
-
-	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
-		      flags, node);
-	return ret;
-}
-EXPORT_SYMBOL(kmalloc_large_node);
-
 #ifdef CONFIG_SLAB_FREELIST_RANDOM
 /* Randomize a generic freelist */
 static void freelist_randomize(unsigned int *list,
diff --git a/mm/slub.c b/mm/slub.c
index 52e2a65b1b11..b44243e7cc5e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3851,14 +3851,6 @@ void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 }
 EXPORT_SYMBOL(kmem_cache_alloc_lru);
 
-void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
-			      int node, size_t orig_size,
-			      unsigned long caller)
-{
-	return slab_alloc_node(s, NULL, gfpflags, node,
-			       caller, orig_size);
-}
-
 void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
 	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, s->object_size);
@@ -3869,6 +3861,124 @@ void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 }
 EXPORT_SYMBOL(kmem_cache_alloc_node);
 
+/*
+ * To avoid unnecessary overhead, we pass through large allocation requests
+ * directly to the page allocator. We use __GFP_COMP, because we will need to
+ * know the allocation order to free the pages properly in kfree.
+ */
+static void *__kmalloc_large_node(size_t size, gfp_t flags, int node)
+{
+	struct page *page;
+	void *ptr = NULL;
+	unsigned int order = get_order(size);
+
+	if (unlikely(flags & GFP_SLAB_BUG_MASK))
+		flags = kmalloc_fix_flags(flags);
+
+	flags |= __GFP_COMP;
+	page = alloc_pages_node(node, flags, order);
+	if (page) {
+		ptr = page_address(page);
+		mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
+				      PAGE_SIZE << order);
+	}
+
+	ptr = kasan_kmalloc_large(ptr, size, flags);
+	/* As ptr might get tagged, call kmemleak hook after KASAN. */
+	kmemleak_alloc(ptr, size, 1, flags);
+	kmsan_kmalloc_large(ptr, size, flags);
+
+	return ptr;
+}
+
+void *kmalloc_large(size_t size, gfp_t flags)
+{
+	void *ret = __kmalloc_large_node(size, flags, NUMA_NO_NODE);
+
+	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
+		      flags, NUMA_NO_NODE);
+	return ret;
+}
+EXPORT_SYMBOL(kmalloc_large);
+
+void *kmalloc_large_node(size_t size, gfp_t flags, int node)
+{
+	void *ret = __kmalloc_large_node(size, flags, node);
+
+	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << get_order(size),
+		      flags, node);
+	return ret;
+}
+EXPORT_SYMBOL(kmalloc_large_node);
+
+static __always_inline
+void *__do_kmalloc_node(size_t size, gfp_t flags, int node,
+			unsigned long caller)
+{
+	struct kmem_cache *s;
+	void *ret;
+
+	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE)) {
+		ret = __kmalloc_large_node(size, flags, node);
+		trace_kmalloc(caller, ret, size,
+			      PAGE_SIZE << get_order(size), flags, node);
+		return ret;
+	}
+
+	if (unlikely(!size))
+		return ZERO_SIZE_PTR;
+
+	s = kmalloc_slab(size, flags, caller);
+
+	ret = slab_alloc_node(s, NULL, flags, node, caller, size);
+	ret = kasan_kmalloc(s, ret, size, flags);
+	trace_kmalloc(caller, ret, size, s->size, flags, node);
+	return ret;
+}
+
+void *__kmalloc_node(size_t size, gfp_t flags, int node)
+{
+	return __do_kmalloc_node(size, flags, node, _RET_IP_);
+}
+EXPORT_SYMBOL(__kmalloc_node);
+
+void *__kmalloc(size_t size, gfp_t flags)
+{
+	return __do_kmalloc_node(size, flags, NUMA_NO_NODE, _RET_IP_);
+}
+EXPORT_SYMBOL(__kmalloc);
+
+void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
+				  int node, unsigned long caller)
+{
+	return __do_kmalloc_node(size, flags, node, caller);
+}
+EXPORT_SYMBOL(__kmalloc_node_track_caller);
+
+void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
+{
+	void *ret = slab_alloc_node(s, NULL, gfpflags, NUMA_NO_NODE,
+					    _RET_IP_, size);
+
+	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
+
+	ret = kasan_kmalloc(s, ret, size, gfpflags);
+	return ret;
+}
+EXPORT_SYMBOL(kmalloc_trace);
+
+void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
+			 int node, size_t size)
+{
+	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, size);
+
+	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, node);
+
+	ret = kasan_kmalloc(s, ret, size, gfpflags);
+	return ret;
+}
+EXPORT_SYMBOL(kmalloc_node_trace);
+
 static noinline void free_to_partial_list(
 	struct kmem_cache *s, struct slab *slab,
 	void *head, void *tail, int bulk_cnt,
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-39-vbabka%40suse.cz.
