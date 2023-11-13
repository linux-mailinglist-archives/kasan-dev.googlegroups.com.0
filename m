Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCHLZGVAMGQE6N3PIAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DACB27EA36F
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:17 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-50a3c3878fcsf1070e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902857; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cult/e3C0afw14wFKEAGwv8ZLnnDRbRGS+XlV2RREv/KjtcSoIoc58+15wTKu9o2v0
         Fq6peaEkGR+QNGRmudR6fxDQFVjzKvf/Z5+V/jzWAGeYolO77Z1Pi0YNfqp+oOWVUeZU
         yDP8tly/i/MmEdmMoP6NXZpYKGv1cGI/54XHCT8IC/su22GYnh2tc68klIbL8ONFbGru
         Z+KCObp3qbiL8R7qHNZ9uKdmSS4810g82FyuxueUf0vn+U5lyjDTLeBWgJ7t9hgOvadC
         lE+b84FaiTHXEvMhMhS11HcP6Azoab2VJfmt6wOcv4HjGdjJJFdARQihK7uIm47dmJLf
         46GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Tw3PKi/Q4qDO/CgxoRwLC8LqiVBdqU7xcuEDO7K8GEQ=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=QrPmRDec/MNwXxQomFaonF7YXiplIipW5a8UjIHn+5sbQcGtU4iYMpymuLnXxxOyxS
         kZhaKR/sUmoERJKwodsMNl8mDfdoaTZgTMIhyKx405Al1HpsSaxDcXdi3/dzgG0Ydhxx
         N5Z7YmU7rMUytDBeEJTT5JqcfWB8ZM/L4G3eE1iYQ08mvMtIM5d+AB//qTuOiYSWR6Tn
         1lQeN0ADMYgDk+ClowjaWOeLszuQYJ7H9eWZxgaz9jrO7XNylNN9KPkMGCZXTd0oADTF
         XG3cr6V0gW+xadMMmfxJHdifN0WmkM1ba6IhPujRrnTkqiS81F6l17TQzhQ9esUyI1KR
         TXjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="olZFTzZ/";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902857; x=1700507657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Tw3PKi/Q4qDO/CgxoRwLC8LqiVBdqU7xcuEDO7K8GEQ=;
        b=X/6l3Cw5onWVJYG3PxUsANBmh0m4qVVhBs26YR3/DUKMa56TnAGCUyhkjscrJ3ZjnH
         X+E1n95gLZron/Bndj2NNQ/wqTrj4O4MTUf+mPpgC3UB6ecLZK00IrvrQScO3xgnEXwV
         /A3cvUsowgdybqa/S2TiQIItmdDzzqyZO9MXv9Wl7DZFlFETSxjttv+80L7inNzSVODM
         qKFuFSM5q2Q2oI5TLDFX9yhjZhtIHq9VLS3UAz1ndtKEPqS248YgNUOAFGzlo57TD4vh
         Zp5ae/PM+hs7A8cN6e6eTGCA2dxDnxP/Hb1D9NFpjIfeQGvSvMCuPiKfH4xYVelui2Ol
         FuRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902857; x=1700507657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tw3PKi/Q4qDO/CgxoRwLC8LqiVBdqU7xcuEDO7K8GEQ=;
        b=BCQ5pbS4CJ4Ba2oPh0BqvuImjcyRGJ8p18pYgwb68JC4m7y3vPC2uW8H6uTXGxTtvN
         NzSUxUbDzvVmWC81z8T4lcUuDEr4fPFdXKYt4vAFXIS6zMF9a5PKmhZH5AnyBPE6Arzk
         5eFATxjVmPAL8Vjg+ekhgbNgolGpDhJt1WjC1cwzqRR06Ar9sxle2d01OR0GC0Shwh6j
         iLoSMPzO6eoaD/nTJfh1xV1kKBPZck5aCqyivpvalOwEuQ8r9hqZFok6DptR6Fqe0g12
         ZzvG4w/rE/Ax2dzexYJCcHO/YSP8DWGSXC8JhZ2NlDkdbbORL3rPMUi5GljVCBH7t+V3
         T4bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx2dkK/N5sRslk7pfM3P04oa8wuUdAVa7f+voWdFXPXMZLc2WH9
	i0yFtcmgWgrWE9rcy6tKWbo=
X-Google-Smtp-Source: AGHT+IFanGaCM77behLmhkaCqTMwT4/3JUMlfMrgL2NUyAu2qAksY4HfhM8YrX4GbjUY83bXWZk2ZA==
X-Received: by 2002:a05:6512:3044:b0:508:2986:44ff with SMTP id b4-20020a056512304400b00508298644ffmr13238lfb.5.1699902857146;
        Mon, 13 Nov 2023 11:14:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e21:b0:507:c72c:9d86 with SMTP id
 i33-20020a0565123e2100b00507c72c9d86ls186297lfv.1.-pod-prod-01-eu; Mon, 13
 Nov 2023 11:14:15 -0800 (PST)
X-Received: by 2002:a05:6512:39c9:b0:50a:7640:6a7f with SMTP id k9-20020a05651239c900b0050a76406a7fmr5860091lfu.12.1699902855129;
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902855; cv=none;
        d=google.com; s=arc-20160816;
        b=G4YKMcmJZmu4umC4SbINNkHNTvOYB8kV1pwwGhy8jBkSAyIumC+/1yOgcIJMEJcJ5a
         b4+CoUpXQ+BieYDs/JRqtm0savyMj4QZcwqZ5/MVq0O7+F+gSQuVqwEjW7pB1gQ6jtwK
         NlR30TA1/GCNzeW7XCIIfx/dHUP9lpssKV/p6hxJkAcNRlqlp751am1c6ujfdPGl+LOh
         xnkwFzJkWaSMzgFcvFRtMzBUu4HBUKQxaT5F4kcBhloi6Ry7SR7CmzH2uh0lyWj4FN0m
         iwNutCp5uFNYthqQyVGiLHZogP2Pcz+BeAhlTY1twjLSvqrH8quhjdzcCKWvVmvCG/hq
         FMCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=DXDFbKsOpifG8/vsvvlxkFBAPHyr1llZIqV93eRLOYA=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=Ha7sdsayY10Ng73478MePWKozZos+XrGyzGZ7X7vFCVZNr5ao/4Yzx5jqBVp2MCohI
         acNBqAYDpuyF7WhGcG1Bubw0ebPRRM8DcgMblq6LIRmhPBkvWw0q5buSPdP/EANvlN2C
         zemlRvKaAuQwm0kvPjb9R47Ha37+B3khkouMgqrlaDyPfExjhXYjNu6Sx4nUFW3rZDyo
         6OIFyGmj1GmHWvxXyOpG4jzd+DLwyemtFzU6gzphgeD+h4pqElfuqaCQPxpTUWh6/54f
         0OiBpMi+g6deWljlu+89RyHpUIgU5HCkyai0uZ7yLeSPpCk5Oc8jFGDMpmkRBdr2eAzh
         eEeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="olZFTzZ/";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id g8-20020a056512118800b005056618eed7si246502lfr.4.2023.11.13.11.14.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:15 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9EC4921923;
	Mon, 13 Nov 2023 19:14:14 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4424113907;
	Mon, 13 Nov 2023 19:14:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id EGvoD4Z1UmVFOgAAMHmgww
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
Subject: [PATCH 15/20] mm/slab: move kfree() from slab_common.c to slub.c
Date: Mon, 13 Nov 2023 20:13:56 +0100
Message-ID: <20231113191340.17482-37-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="olZFTzZ/";
       dkim=neutral (no key) header.i=@suse.cz;       spf=softfail
 (google.com: domain of transitioning vbabka@suse.cz does not designate
 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

This should result in better code. Currently kfree() makes a function
call between compilation units to __kmem_cache_free() which does its own
virt_to_slab(), throwing away the struct slab pointer we already had in
kfree(). Now it can be reused. Additionally kfree() can now inline the
whole SLUB freeing fastpath.

Also move over free_large_kmalloc() as the only callsites are now in
slub.c, and make it static.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab.h        |  4 ----
 mm/slab_common.c | 45 ------------------------------------------
 mm/slub.c        | 51 +++++++++++++++++++++++++++++++++++++++++++-----
 3 files changed, 46 insertions(+), 54 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 1b09fd1b4b04..179467e8aacc 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -394,8 +394,6 @@ struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller);
 void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
 			      int node, size_t orig_size,
 			      unsigned long caller);
-void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller);
-
 gfp_t kmalloc_fix_flags(gfp_t flags);
 
 /* Functions provided by the slab allocators */
@@ -558,8 +556,6 @@ static inline int memcg_alloc_slab_cgroups(struct slab *slab,
 }
 #endif /* CONFIG_MEMCG_KMEM */
 
-void free_large_kmalloc(struct folio *folio, void *object);
-
 size_t __ksize(const void *objp);
 
 static inline size_t slab_ksize(const struct kmem_cache *s)
diff --git a/mm/slab_common.c b/mm/slab_common.c
index bbc2e3f061f1..f4f275613d2a 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -963,22 +963,6 @@ void __init create_kmalloc_caches(slab_flags_t flags)
 	slab_state = UP;
 }
 
-void free_large_kmalloc(struct folio *folio, void *object)
-{
-	unsigned int order = folio_order(folio);
-
-	if (WARN_ON_ONCE(order == 0))
-		pr_warn_once("object pointer: 0x%p\n", object);
-
-	kmemleak_free(object);
-	kasan_kfree_large(object);
-	kmsan_kfree_large(object);
-
-	mod_lruvec_page_state(folio_page(folio, 0), NR_SLAB_UNRECLAIMABLE_B,
-			      -(PAGE_SIZE << order));
-	__free_pages(folio_page(folio, 0), order);
-}
-
 static void *__kmalloc_large_node(size_t size, gfp_t flags, int node);
 static __always_inline
 void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller)
@@ -1023,35 +1007,6 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
 }
 EXPORT_SYMBOL(__kmalloc_node_track_caller);
 
-/**
- * kfree - free previously allocated memory
- * @object: pointer returned by kmalloc() or kmem_cache_alloc()
- *
- * If @object is NULL, no operation is performed.
- */
-void kfree(const void *object)
-{
-	struct folio *folio;
-	struct slab *slab;
-	struct kmem_cache *s;
-
-	trace_kfree(_RET_IP_, object);
-
-	if (unlikely(ZERO_OR_NULL_PTR(object)))
-		return;
-
-	folio = virt_to_folio(object);
-	if (unlikely(!folio_test_slab(folio))) {
-		free_large_kmalloc(folio, (void *)object);
-		return;
-	}
-
-	slab = folio_slab(folio);
-	s = slab->slab_cache;
-	__kmem_cache_free(s, (void *)object, _RET_IP_);
-}
-EXPORT_SYMBOL(kfree);
-
 /**
  * __ksize -- Report full size of underlying allocation
  * @object: pointer to the object
diff --git a/mm/slub.c b/mm/slub.c
index 0dbb966e28a7..52e2a65b1b11 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4184,11 +4184,6 @@ static inline struct kmem_cache *cache_from_obj(struct kmem_cache *s, void *x)
 	return cachep;
 }
 
-void __kmem_cache_free(struct kmem_cache *s, void *x, unsigned long caller)
-{
-	slab_free(s, virt_to_slab(x), x, NULL, &x, 1, caller);
-}
-
 void kmem_cache_free(struct kmem_cache *s, void *x)
 {
 	s = cache_from_obj(s, x);
@@ -4199,6 +4194,52 @@ void kmem_cache_free(struct kmem_cache *s, void *x)
 }
 EXPORT_SYMBOL(kmem_cache_free);
 
+static void free_large_kmalloc(struct folio *folio, void *object)
+{
+	unsigned int order = folio_order(folio);
+
+	if (WARN_ON_ONCE(order == 0))
+		pr_warn_once("object pointer: 0x%p\n", object);
+
+	kmemleak_free(object);
+	kasan_kfree_large(object);
+	kmsan_kfree_large(object);
+
+	mod_lruvec_page_state(folio_page(folio, 0), NR_SLAB_UNRECLAIMABLE_B,
+			      -(PAGE_SIZE << order));
+	__free_pages(folio_page(folio, 0), order);
+}
+
+/**
+ * kfree - free previously allocated memory
+ * @object: pointer returned by kmalloc() or kmem_cache_alloc()
+ *
+ * If @object is NULL, no operation is performed.
+ */
+void kfree(const void *object)
+{
+	struct folio *folio;
+	struct slab *slab;
+	struct kmem_cache *s;
+	void *x = (void *)object;
+
+	trace_kfree(_RET_IP_, object);
+
+	if (unlikely(ZERO_OR_NULL_PTR(object)))
+		return;
+
+	folio = virt_to_folio(object);
+	if (unlikely(!folio_test_slab(folio))) {
+		free_large_kmalloc(folio, (void *)object);
+		return;
+	}
+
+	slab = folio_slab(folio);
+	s = slab->slab_cache;
+	slab_free(s, slab, x, NULL, &x, 1, _RET_IP_);
+}
+EXPORT_SYMBOL(kfree);
+
 struct detached_freelist {
 	struct slab *slab;
 	void *tail;
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-37-vbabka%40suse.cz.
