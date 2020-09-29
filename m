Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3PRZT5QKGQEZSYUT5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 24C9127CF5A
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 15:38:54 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id d13sf1750306wrr.23
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 06:38:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601386734; cv=pass;
        d=google.com; s=arc-20160816;
        b=iBxtgIUB5f4QiiZd7Y6pBhPJfb9ASQZddixaU6s/vxcxTPxhBE8Fcahs+QtJZlbXYW
         b4YETD/zgNvIvLhQJiyJxDxrdndZqYDAE6FLOqG55OrUY3mRfGq6y75OabAUmLGVcOsy
         nQhFJnQn85lKke1HzREsRxK8L7HHCiO513FWGUHRDge86zecDtXd8yFBsAo3mLUIj/Km
         h6Zem+XE7JO55Pwz/W3jGsBOJMlXZY/yq86Qe1jx4rMmMdP7dCX2JqJe2QG7dH9XMxI4
         dq7C25E34rKJYvmS8xAIQWxFT07o02C/R8kzzl3YzYmikpfr14gan9mCPXCYp18UkGBj
         XMRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ljdLyvGjIDv2KumWpqNImBU55SWg8/t6+j6CCJ2JafA=;
        b=jJV97FwbuQSHESJ5AG/gY6Ucwtj5a0wBOG2OYCd+yj+EKo+d40UEmzG9hvCsXj8VvH
         znizXJpXXGcAYSgiRCzxxC4sq65OXbGWzJFUUmecDscfIMAyRh6FzIGVcYCzwU5qdKmZ
         Pij2EwJwBkPJQgXIQ4+vIjLaOzxHfGhHRwsb3gP5em4XhHG8VzOMPRRfABswBraBvVah
         SIQQl9nVTaTn19C5K9CJZBYUWz9PFIP9MJ+xW7oLdMO1YqHIYvElktnwtF1op7D65C4Y
         lAmkNKJdtRYtPXC6UM7NlUl4wN7HN/ryicN0cvkzYQn9T0pJolmM691qER1gKR+9+pCD
         CUxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P3GJtu0X;
       spf=pass (google.com: domain of 37dhzxwukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37DhzXwUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ljdLyvGjIDv2KumWpqNImBU55SWg8/t6+j6CCJ2JafA=;
        b=seKuuE2UDatz9y2LkYHER2R6KQV9FOeWozhXqVV6TmCpOerELLoddkDlWO8mZkhlvl
         Shga7OGKE2EUjMxBI7VZ8elUFWw+GBgrPotyASztqRDkHVujtFv/9j68VQhs3S/STt2g
         HaYlnjczvIqbfrn7MTa5bZZY8WRMEr8nxQC6muPCnvXRqtVcGpjb8eXEcVhXFqVk6et2
         bTLslVqfS9QuFDYqfWZsPg889rs4XfPiqCINAkiSzUIa1FEWACBBrD0Y7FkrSuybwOuz
         /lQavq8TYV8rsT3poCV2o//1ehlSW//G97hBw3tiPLdtyIro0Xa9zjGfCEUSje6O4+Jx
         ynlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ljdLyvGjIDv2KumWpqNImBU55SWg8/t6+j6CCJ2JafA=;
        b=pmvcx3QTIMoGCyIO+TjqlPVxOMJHYTPTeCtP77bQNunPfu8b+UqAgmqRtY1OOJw2DG
         TNeW+nCwIkFCX4z45pTvrVk4YUP20kTLYOOWqVlxW5cWx/oTwyQDO4jbcmv/Iqk6FIA3
         D9r0lWH6JmT4g834lUocu/Vljzw3aeXbk9DRvmcs3eJ/+C6xWFyjf7LYY2kkpglz1cEP
         m+Z8TkMcNsZURWEa7lGIp19oE0QrHIhpc6xbeyVsJFzL+oC6MBuTTL6NxkeSnm/mnlSd
         1KSc+sphfLnb34RqrwiARYiFvfZO8QY2nV3FxHum3a4edqWLmaK+XU0gp1ByXf8ryzqz
         br+Q==
X-Gm-Message-State: AOAM533OM3rBqcacvdocNDfgyjFo+6aseOT50qSo4fU4WLPI3A3JoT54
	XCAAF/DwpMrtPRViqdTT7Wo=
X-Google-Smtp-Source: ABdhPJwv4QKC3jpgQf4uD9SsDrDyY29zfgZ6eKS3/92eSUnT05AwihXfm3GDKXIvMCfsKhFBTbO6nA==
X-Received: by 2002:a1c:e1c2:: with SMTP id y185mr4852707wmg.182.1601386733793;
        Tue, 29 Sep 2020 06:38:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c2c1:: with SMTP id s184ls1832919wmf.2.canary-gmail;
 Tue, 29 Sep 2020 06:38:52 -0700 (PDT)
X-Received: by 2002:a1c:3505:: with SMTP id c5mr4922936wma.65.1601386732748;
        Tue, 29 Sep 2020 06:38:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601386732; cv=none;
        d=google.com; s=arc-20160816;
        b=RY0wAHJc6608/UgJZ5mP16pFt9CvDqRmOxjwAzoM9t1y77Gpce6HDgV1FL6zfs6aCz
         jtJ0hwSaeCfyt1gwhEKeh/srVnkEbvkA07W6pPutRukD4c/XrVALxS8AHsLTxLbTQYeU
         V5Zn1xiDLMOQinH682+ZiZBL3XtXPsUsjhGAjFfcIUg5E/0i6fRqMxQyCxslyDATzoWI
         f6BhQvKNjI3dccyaRAEedPIzHmBnwVunlK4V2g9Iiqc52eHoAWzekMjgE3ij/8ofJt9S
         fbjF5jOBIuBum0XxZEkYgZvU4vTGvReSfS1LuujfcIou48GGa51XYA04bgnJygulaVkp
         24ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=RyhekuRkgmFAPj0MnrvGu5klxhimFNDAR1CWyJxk0no=;
        b=w/U36ipG5tivuK5ErDBgRP15OqYxemeCa+0b7lsVTuCSh7AyY2pVfpu3ru8y8MBPBm
         sbqKTHhIiwYL6ITtKu3KhIsx0a5jq7bQo8BkLV5v8esxPPTe6Uc/C1QO66AZ3SHuMHqn
         oIYS7fU9UDX2x/MPxArlglgJClC3aoereh4jtR807+SyhNVL9GLiEr07hoB3TXyu1b2w
         3+J6E2aBWeUWqC+PHYAsVjrIqYKaK5Ld7hw/9QTT6bq/IMO3YGN9RtP2H6L0zkmM1tf+
         idp0LY/Zm93WywkyvRkocViDc2miuZ88hHyNSnI/pm6vnwlIytc9lXdM0HI+dC7XjJ5J
         sVWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P3GJtu0X;
       spf=pass (google.com: domain of 37dhzxwukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37DhzXwUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id b1si135643wmj.1.2020.09.29.06.38.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 06:38:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37dhzxwukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m19so1847632wmg.6
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 06:38:52 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c453:: with SMTP id l19mr4414928wmi.163.1601386732135;
 Tue, 29 Sep 2020 06:38:52 -0700 (PDT)
Date: Tue, 29 Sep 2020 15:38:07 +0200
In-Reply-To: <20200929133814.2834621-1-elver@google.com>
Message-Id: <20200929133814.2834621-5-elver@google.com>
Mime-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 04/11] mm, kfence: insert KFENCE hooks for SLAB
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=P3GJtu0X;       spf=pass
 (google.com: domain of 37dhzxwukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=37DhzXwUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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
v3:
* Rewrite patch description to clarify need for 'orig_size'
  [reported by Christopher Lameter].
---
 mm/slab.c        | 46 ++++++++++++++++++++++++++++++++++------------
 mm/slab_common.c |  6 +++++-
 2 files changed, 39 insertions(+), 13 deletions(-)

diff --git a/mm/slab.c b/mm/slab.c
index 3160dff6fd76..30aba06ae02b 100644
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
@@ -3206,7 +3207,7 @@ static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
 }
 
 static __always_inline void *
-slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
+slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid, size_t orig_size,
 		   unsigned long caller)
 {
 	unsigned long save_flags;
@@ -3219,6 +3220,10 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
 	if (unlikely(!cachep))
 		return NULL;
 
+	ptr = kfence_alloc(cachep, orig_size, flags);
+	if (unlikely(ptr))
+		goto out_hooks;
+
 	cache_alloc_debugcheck_before(cachep, flags);
 	local_irq_save(save_flags);
 
@@ -3251,6 +3256,7 @@ slab_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
 	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && ptr)
 		memset(ptr, 0, cachep->object_size);
 
+out_hooks:
 	slab_post_alloc_hook(cachep, objcg, flags, 1, &ptr);
 	return ptr;
 }
@@ -3288,7 +3294,7 @@ __do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 #endif /* CONFIG_NUMA */
 
 static __always_inline void *
-slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
+slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size, unsigned long caller)
 {
 	unsigned long save_flags;
 	void *objp;
@@ -3299,6 +3305,10 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
 	if (unlikely(!cachep))
 		return NULL;
 
+	objp = kfence_alloc(cachep, orig_size, flags);
+	if (unlikely(objp))
+		goto leave;
+
 	cache_alloc_debugcheck_before(cachep, flags);
 	local_irq_save(save_flags);
 	objp = __do_cache_alloc(cachep, flags);
@@ -3309,6 +3319,7 @@ slab_alloc(struct kmem_cache *cachep, gfp_t flags, unsigned long caller)
 	if (unlikely(slab_want_init_on_alloc(flags, cachep)) && objp)
 		memset(objp, 0, cachep->object_size);
 
+leave:
 	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp);
 	return objp;
 }
@@ -3414,6 +3425,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
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
@@ -3479,7 +3495,7 @@ void ___cache_free(struct kmem_cache *cachep, void *objp,
  */
 void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
 {
-	void *ret = slab_alloc(cachep, flags, _RET_IP_);
+	void *ret = slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret,
 			       cachep->object_size, cachep->size, flags);
@@ -3512,7 +3528,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 
 	local_irq_disable();
 	for (i = 0; i < size; i++) {
-		void *objp = __do_cache_alloc(s, flags);
+		void *objp = kfence_alloc(s, s->object_size, flags) ?: __do_cache_alloc(s, flags);
 
 		if (unlikely(!objp))
 			goto error;
@@ -3545,7 +3561,7 @@ kmem_cache_alloc_trace(struct kmem_cache *cachep, gfp_t flags, size_t size)
 {
 	void *ret;
 
-	ret = slab_alloc(cachep, flags, _RET_IP_);
+	ret = slab_alloc(cachep, flags, size, _RET_IP_);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc(_RET_IP_, ret,
@@ -3571,7 +3587,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
  */
 void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
 {
-	void *ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
+	void *ret = slab_alloc_node(cachep, flags, nodeid, cachep->object_size, _RET_IP_);
 
 	trace_kmem_cache_alloc_node(_RET_IP_, ret,
 				    cachep->object_size, cachep->size,
@@ -3589,7 +3605,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *cachep,
 {
 	void *ret;
 
-	ret = slab_alloc_node(cachep, flags, nodeid, _RET_IP_);
+	ret = slab_alloc_node(cachep, flags, nodeid, size, _RET_IP_);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc_node(_RET_IP_, ret,
@@ -3650,7 +3666,7 @@ static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
 	cachep = kmalloc_slab(size, flags);
 	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
 		return cachep;
-	ret = slab_alloc(cachep, flags, caller);
+	ret = slab_alloc(cachep, flags, size, caller);
 
 	ret = kasan_kmalloc(cachep, ret, size, flags);
 	trace_kmalloc(caller, ret,
@@ -4138,18 +4154,24 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 			 bool to_user)
 {
 	struct kmem_cache *cachep;
-	unsigned int objnr;
+	unsigned int objnr = 0;
 	unsigned long offset;
+	bool is_kfence = is_kfence_address(ptr);
 
 	ptr = kasan_reset_tag(ptr);
 
 	/* Find and validate object. */
 	cachep = page->slab_cache;
-	objnr = obj_to_index(cachep, page, (void *)ptr);
-	BUG_ON(objnr >= cachep->num);
+	if (!is_kfence) {
+		objnr = obj_to_index(cachep, page, (void *)ptr);
+		BUG_ON(objnr >= cachep->num);
+	}
 
 	/* Find offset within object. */
-	offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
+	if (is_kfence_address(ptr))
+		offset = ptr - kfence_object_start(ptr);
+	else
+		offset = ptr - index_to_obj(cachep, page, objnr) - obj_offset(cachep);
 
 	/* Allow address range falling entirely within usercopy region. */
 	if (offset >= cachep->useroffset &&
diff --git a/mm/slab_common.c b/mm/slab_common.c
index f9ccd5dc13f3..6e35e273681a 100644
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
@@ -448,6 +449,9 @@ static int shutdown_cache(struct kmem_cache *s)
 	/* free asan quarantined objects */
 	kasan_cache_shutdown(s);
 
+	if (!kfence_shutdown_cache(s))
+		return -EBUSY;
+
 	if (__kmem_cache_shutdown(s) != 0)
 		return -EBUSY;
 
@@ -1171,7 +1175,7 @@ size_t ksize(const void *objp)
 	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !__kasan_check_read(objp, 1))
 		return 0;
 
-	size = __ksize(objp);
+	size = kfence_ksize(objp) ?: __ksize(objp);
 	/*
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929133814.2834621-5-elver%40google.com.
