Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUGX4D6AKGQERR6R72Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id A256629B01F
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 15:16:48 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id s25sf856306ljo.13
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:16:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603808208; cv=pass;
        d=google.com; s=arc-20160816;
        b=ddYdiRJSp5X3Il0cJMxP2SRQH19uE1/oIuPGPUbnPe/N7Q1ikCEMtPJ4V2it+pYiIA
         NZRVN6E892mFnQRPYveTr4Qiv/oYklR2wLb7YvQ3UaYfXCwhCpRuPxbHtWewcUtKsOYk
         AwDAjm01JNe0cONFLNn3Rs/JJI8wPiSJAWz3S2eKD2se5p78ih2lrzGSliOS0OiGjtbI
         ck8/RkYXcGja7eRXWtITSQ6FvgapGOaDC25tK5TPZISVlz+bcZrQ4YUAJb93z7VRHf0z
         QblzJQFrhONR4TK0oB/2BnsIV2645VUDeHRBs16Nxn8qiKYSsb3jmf6EFik22a1YvQ3J
         5Z+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Z3KRaOxgj2owDNiX7j4zjdADQvwPJ2vZdAXhHXpAGQo=;
        b=0qMtaDbJTAfLGUlcXZPHAkDuhyArLM5cx0u+asxdTPRm8wv5JlCHPeAyivOh855P8h
         +gIuzuwj+yRlXQjMhHPqtmR0fmx/BtoRr2cUq0wh0HqibEGbNL5073bhGd5KKkueDjfE
         hUGQON34UgrzO7wzA6EssINW7r49TQTqPZkIJitoZL5i7UF+//d+wCChywU9fFFXxjed
         E/NK8irtyTpREplT64etH9y/HWqcocsW69qSvTZy5AEERm7CRRTwtstwW+hlT0o2l7Os
         P0lkK5ehnEiIodgr/v+nVt6iWvm/WtnnMZ6lXzfrRbaZLGMv6Lz8P4oxjhHOyfQ09rSw
         45fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pmR1mwCm;
       spf=pass (google.com: domain of 3ziuyxwukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ziuYXwUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z3KRaOxgj2owDNiX7j4zjdADQvwPJ2vZdAXhHXpAGQo=;
        b=MsASYJCMBJvtKNFzc0H+rYb5LbCubLHNQjQHF61E8Johs0VfxNoXDp215sD7vgQG9W
         cxUF+4JSjZZRBiCDQy1LsOnutV7PmRMx2BYRjfzE6mEqLmIYoSKPbM2xT1G54HCPG2LZ
         YxQ9NjQFbCdpHH9RqpbgW1WNIxELByB7SNS1uqVWe9quJnIULuNcFXaLi3g2klrWHuzC
         rFn35potg8Q902O48eRmHbCc8lHIve5VTgTJQRqCtD3Tb8vnGgSY0yy0pRy+mT7BBomm
         9IMm0pgM7X6pkn24g7FCmAQvU2Rc/E6voiQOdOsdklQ1r7SzELtdsp54llLFzb4wxrSX
         CwAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z3KRaOxgj2owDNiX7j4zjdADQvwPJ2vZdAXhHXpAGQo=;
        b=akKHORbDTNY7i6x10YN+P0izwkAMiAFUXp37JXvknc2bzB4/hxLDdCQGgk9daZA8a+
         iZcASlGLs4LPIE12Ep9t/aD9Utg6LB8DK8AxIeSle8h78mn522xwerLvxO19g0h7K1XD
         Qr5lgRsFhHGUryYrfoANKWjGIugzELn1jJb64xq+C++jqg/+K1Dot0tOgxCJPHR3NQlp
         GktV5IxGOn3RlskltHWLCpalCJNNStq6zGqPJk83IQ8Y0fX9Rsbgzra6cbASNLjWPs02
         yDUSOLFZVb/EbNEAaPe0pFz2WVUKvrF3zsgbI1T38jDSum4FOK7VhbOhQufzOESKVyrz
         3qiA==
X-Gm-Message-State: AOAM530rpOhq2XaqH0j48Qt5CeyYrfTb2V0vAgLyGbXnqsue+7cFkGse
	Hb0nsESm9WYqM7h27x4ssR8=
X-Google-Smtp-Source: ABdhPJzS2rUs1d5kVzPh2cRByIpofUngmujIlgS832/C1vnv34H7a1wFRfF83IVdPHTR0Hf/jTWy2w==
X-Received: by 2002:a2e:7217:: with SMTP id n23mr1218414ljc.43.1603808208205;
        Tue, 27 Oct 2020 07:16:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:890b:: with SMTP id d11ls362849lji.6.gmail; Tue, 27 Oct
 2020 07:16:47 -0700 (PDT)
X-Received: by 2002:a2e:9948:: with SMTP id r8mr1242367ljj.175.1603808207021;
        Tue, 27 Oct 2020 07:16:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603808207; cv=none;
        d=google.com; s=arc-20160816;
        b=IFGlktD2shNE3dhrbPxrceqPgP5B1/gY2tFu6d+Z7S/tKrNxzg+MmmiX2NjL8uhMg1
         2aLB4udUyUc3TpIbEa/W6Eqp5Ye98/FknOnS2jYQq0vFFnqVcQO9i15IrgsKmKI7xB6x
         9RCPswJSZdoZxs8eret3QsxJpXTHwoDLsO3rmy5MWJEB9jnYbUo1XQf9Kuri131nsyw4
         xubzwreLiq9Xq1YnbPxukLWctyz7yVQ1cYfx+eJdhse3EL0NjqP1WNglOMSQDkRVg0ou
         rbChDxWQZlFhQtmTIlIzjJCIUv/V2ylOx3WcF1EhStr81FpRaQMcu/bpx31CFhS0EmvV
         f8Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Ky419dSguFWRYNd65BY7RJSEwVlIKUdqUW3Z61seKFA=;
        b=tctiMxJQ8AMXTwwwDP1s8J8ve5CKDlVDIuhYRnuXjofw4ln8R6HPdgxd4mq1jDgNw3
         MVcYioFPz8cB4X/MKDv/wV+FZcL6KgdDwvSpk2DD5B2Wy1IoEvVMWJpqtihWkcS79dOH
         auBdZpOV3GpWhWpIHQkxFkiAgXuML3CJ8B8BHFiIF/HDaSJXHvjeBoxZNBD6LsgAOWcY
         3wtMVDASaTQnWt8ay0eX8HGFb7ioimjFKqs6WP1OfNJXlA/Tyx51rJReEcETUl3AeT6m
         Qnwsv1VG5fDOso1CNBGHFXXlwGLdv4r0q29qGhhN9Up01+9zHvpDCe4QX9uZZwn9GyEM
         7zIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pmR1mwCm;
       spf=pass (google.com: domain of 3ziuyxwukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ziuYXwUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id x19si59590ljh.2.2020.10.27.07.16.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 07:16:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ziuyxwukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z7so633639wme.8
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 07:16:46 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a5d:4dc7:: with SMTP id f7mr2649460wru.375.1603808206262;
 Tue, 27 Oct 2020 07:16:46 -0700 (PDT)
Date: Tue, 27 Oct 2020 15:16:01 +0100
In-Reply-To: <20201027141606.426816-1-elver@google.com>
Message-Id: <20201027141606.426816-5-elver@google.com>
Mime-Version: 1.0
References: <20201027141606.426816-1-elver@google.com>
X-Mailer: git-send-email 2.29.0.rc2.309.g374f81d7ae-goog
Subject: [PATCH v5 4/9] mm, kfence: insert KFENCE hooks for SLAB
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pmR1mwCm;       spf=pass
 (google.com: domain of 3ziuyxwukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ziuYXwUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Alexander Potapenko <glider@google.com>

Inserts KFENCE hooks into the SLAB allocator.

To pass the originally requested size to KFENCE, add an argument
'orig_size' to slab_alloc*(). The additional argument is required to
preserve the requested original size for kmalloc() allocations, which
uses size classes (e.g. an allocation of 272 bytes will return an object
of size 512). Therefore, kmem_cache::size does not represent the
kmalloc-caller's requested size, and we must introduce the argument
'orig_size' to propagate the originally requested size to KFENCE.

Without the originally requested size, we would not be able to detect
out-of-bounds accesses for objects placed at the end of a KFENCE object
page if that object is not equal to the kmalloc-size class it was
bucketed into.

When KFENCE is disabled, there is no additional overhead, since
slab_alloc*() functions are __always_inline.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v5:
* New kfence_shutdown_cache(): we need to defer kfence_shutdown_cache()
  to before the cache is actually freed. In case of SLAB_TYPESAFE_BY_RCU,
  the objects may still legally be used until the next RCU grace period.
* Fix objs_per_slab_page for kfence objects.
* Revert and use fixed obj_to_index() in __check_heap_object().

v3:
* Rewrite patch description to clarify need for 'orig_size'
  [reported by Christopher Lameter].
---
 include/linux/slab_def.h |  3 +++
 mm/slab.c                | 37 ++++++++++++++++++++++++++++---------
 mm/slab_common.c         |  5 ++++-
 3 files changed, 35 insertions(+), 10 deletions(-)

diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index 9eb430c163c2..3aa5e1e73ab6 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_SLAB_DEF_H
 #define	_LINUX_SLAB_DEF_H
 
+#include <linux/kfence.h>
 #include <linux/reciprocal_div.h>
 
 /*
@@ -114,6 +115,8 @@ static inline unsigned int obj_to_index(const struct kmem_cache *cache,
 static inline int objs_per_slab_page(const struct kmem_cache *cache,
 				     const struct page *page)
 {
+	if (is_kfence_address(page_address(page)))
+		return 1;
 	return cache->num;
 }
 
diff --git a/mm/slab.c b/mm/slab.c
index b1113561b98b..ebff1c333558 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -100,6 +100,7 @@
 #include	<linux/seq_file.h>
 #include	<linux/notifier.h>
 #include	<linux/kallsyms.h>
+#include	<linux/kfence.h>
 #include	<linux/cpu.h>
 #include	<linux/sysctl.h>
 #include	<linux/module.h>
@@ -3208,7 +3209,7 @@ static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
 }
 
 static __always_inline void *
-slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
+slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_size,
 		   unsigned long caller)
 {
 	unsigned long save_flags;
@@ -3221,6 +3222,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
 	if (unlikely(!cachep))
 		return NULL;
 
+	ptr = kfence_alloc(cachep, orig_size, flags);
+	if (unlikely(ptr))
+		goto out_hooks;
+
 	cache_alloc_debugcheck_before(cachep, flags);
 	local_irq_save(save_flags);
 
@@ -3253,6 +3258,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
 	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
 		memset(ptr, 0, cachep->object_size);
 
+out_hooks:
 	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
 	return ptr;
 }
@@ -3290,7 +3296,7 @@ __do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 #endif /* CONFIG_NUMA */
 
 static __always_inline void *
-slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
+slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned long caller)
 {
 	unsigned long save_flags;
 	void *objp;
@@ -3301,6 +3307,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
 	if (unlikely(!cachep))
 		return NULL;
 
+	objp = kfence_alloc(cachep, orig_size, flags);
+	if (unlikely(objp))
+		goto out;
+
 	cache_alloc_debugcheck_before(cachep, flags);
 	local_irq_save(save_flags);
 	objp = __do_cache_alloc(cachep, flags);
@@ -3311,6 +3321,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
 	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
 		memset(objp, 0, cachep->object_size);
 
+out:
 	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
 	return objp;
 }
@@ -3416,6 +3427,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	if (kfence_free(objp)) {
+		kmemleak_free_recursive(objp, cachep->flags);
+		return;
+	}
+
 	/* Put the object into the quarantine, don't touch it for now. */
 	if (kasan_slab_free(cachep, objp, _RET_IP_))
 		return;
@@ -3481,7 +3497,7 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
  */
 void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 {
-	void *ret = slab_alloc(cachep, flags, _RET_IP_);
+	void *ret = slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret,
 			       cachep->object_size, cachep->size, flags);
@@ -3514,7 +3530,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
 	local_irq_disable();
 	for (i = 0; i < size; i++) {
-		void *objp = __do_cache_alloc(s, flags);
+		void *objp = kfence_alloc(s, s->object_size, flags) ?: __do_cache_alloc(s, flags);
 
 		if (unlikely(!objp))
 			goto error;
@@ -3547,7 +3563,7 @@ kmem_cache_alloc_trace(struct kmem_cache *cachep, gfp_t flags, size_t size)
 {
 	void *ret;
 
-	ret = slab_alloc(cachep, flags, _RET_IP_);
+	ret = slab_alloc(cachep, flags, size, _RET_IP_);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc(_RET_IP_, ret,
@@ -3573,7 +3589,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
  */
 void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
 {
-	void *ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
+	void *ret = slab_alloc_node(cachep, flags, nodeid, cachep->object_size, _RET_IP_);
 
 	trace_kmem_cache_alloc_node(_RET_IP_, ret,
 				    cachep->object_size, cachep->size,
@@ -3591,7 +3607,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *cachep,
 {
 	void *ret;
 
-	ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
+	ret = slab_alloc_node(cachep, flags, nodeid, size, _RET_IP_);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc_node(_RET_IP_, ret,
@@ -3652,7 +3668,7 @@ static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
 	cachep = kmalloc_slab(size, flags);
 	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
 		return cachep;
-	ret = slab_alloc(cachep, flags, caller);
+	ret = slab_alloc(cachep, flags, size, caller);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc(caller, ret,
@@ -4151,7 +4167,10 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 	BUG_ON(objnr >= cachep->num);
 
 	/* Find offset within object. */
-	offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
+	if (is_kfence_address(ptr))
+		offset = ptr - kfence_object_start(ptr);
+	else
+		offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
 
 	/* Allow address range falling entirely within usercopy region. */
 	if (offset >= cachep->useroffset &&
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f9ccd5dc13f3..13125773dae2 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -12,6 +12,7 @@
 #include <linux/memory.h>
 #include <linux/cache.h>
 #include <linux/compiler.h>
+#include <linux/kfence.h>
 #include <linux/module.h>
 #include <linux/cpu.h>
 #include <linux/uaccess.h>
@@ -435,6 +436,7 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 	rcu_barrier();
 
 	list_for_each_entry_safe(s, s2, &to_destroy, list) {
+		kfence_shutdown_cache(s);
 #ifdef SLAB_SUPPORTS_SYSFS
 		sysfs_slab_release(s);
 #else
@@ -460,6 +462,7 @@ static int shutdown_cache(struct kmem_cache *s)
 		list_add_tail(&s->list, &slab_caches_to_rcu_destroy);
 		schedule_work(&slab_caches_to_rcu_destroy_work);
 	} else {
+		kfence_shutdown_cache(s);
 #ifdef SLAB_SUPPORTS_SYSFS
 		sysfs_slab_unlink(s);
 		sysfs_slab_release(s);
@@ -1171,7 +1174,7 @@ size_t ksize(const void *objp)
 	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !__kasan_check_read(objp, 1))
 		return 0;
 
-	size = __ksize(objp);
+	size = kfence_ksize(objp) ?: __ksize(objp);
 	/*
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
-- 
2.29.0.rc2.309.g374f81d7ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027141606.426816-5-elver%40google.com.
