Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAXR3D5AKGQESMT4F7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 10ACE25FB90
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:24 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id l8sf8082802ioa.11
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486083; cv=pass;
        d=google.com; s=arc-20160816;
        b=mmEurmyzTQO1GpkeERcF98Q0drS6DgCM7Ni9y3+jfkYYQpReozn2cI2zn5xdeN+xme
         W5OHhdtKmOubEh5rt0OEdDjNSZ8IqFMd0BHKhvNLl96lqKFlmNzTReqYVAibY5Ru98Z9
         Bbyj2TeOoJm4pZWHvrk4EMHe4wlXITUuz+2836C+dVQIvtcROL/SqtRWL/KcU5JrdG/F
         E8C/wve2iOM9e+Ciqkj1pyUYhAPweRiV+XPm2fEpfAZBs9UeQz17u1+BAVGE3iOaTQhl
         iTZ4+gHoqHwON4ikl++UBUljWPF67+OVBlF3AwS1F6GcoSuBH1FbN0q0HG0eWHbHi2yt
         5v+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OiMxJ5ydzQhulh4/Q1EVNcoerFOBqv+CYME4A8U+WBI=;
        b=BnP5ylqN+Z6cJV104fel01caJTYY6JYK8kcY1I9zjvgo+Oc2KsF18yzR7bPpXsSp6a
         D7uOB1u//MaB99v/OtfXjxs1EX/AStKUytFDnwlp11aKfh8REx96Z515taH9f+Hv79kA
         VAjhnJEudPidaCZ3OLQxHrzZjeOUr2XLMwgKwiKjZXAzXbU3nKgjL16/X6U2guYB2hZ/
         i+c0iRe/c4019oJHR1foDsvPhOeEfZE7n6Ln76L1g8xl6+fJCDDdBtZpfY/0fbOXKEQ0
         EhB+p0yZ5OxkktndmpGM68rkJDnBlVrJa4uypvSPZxypz0pfYb+YDXDBARhjGYSTwR5P
         oGyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KvR1k1HI;
       spf=pass (google.com: domain of 3gthwxwukcuwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3gThWXwUKCUwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OiMxJ5ydzQhulh4/Q1EVNcoerFOBqv+CYME4A8U+WBI=;
        b=LPpmpfwZkFMOcW2KIwNOx331WhnPxSWQCfAmF1I4vz82f1svli6z12PTsIjSLCUPs4
         7qtvznC6SIYbPSAv83rIAjvnN5YgbBBlJVfM9pxPpHaXZvc9uKSxYQ6G1LVA5ZSzZdOm
         XOi+PCB6yqxbSt2H37vYViKwNKcuHlbsqgo/saW0opL4PeURSMOCG3OyjKy4B0kkRK0X
         ae8jzHSwrbDtx+4DCkxu95FKjVHM9oc6POE9G/6NK1E9uMJCCSr+qAAL3LSTRCNAGwOd
         HL7Am6jv6D1WktUIgmdxARbCTHVNprFLvAsUYzEocjFTV0uwpPxESZN03DD+RCZl225+
         gwAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OiMxJ5ydzQhulh4/Q1EVNcoerFOBqv+CYME4A8U+WBI=;
        b=CPRnixcDwy7ExJjI4KZg1q3uuLB+lKnCaNm5ZQLy+pNQBGIgKa79iswMBMuKB1sogg
         AiXFdRXZdkzFF65aVh2P/lyiy17h1QoWnMGnCkOBWgfdIZZMYm6FgK/Ol0f2tTsKmEcz
         9eUCaomfPXD9yI9BJU9KKd1FITqFaepVCaLgn3WkA00ml3SMgrD3iYd9m4Cf6iJGd/um
         3UkzTfqLUqH5EXk4iSfZcv0X1v3Z7qjFydcKyLzggww+joc85aLwssOoL/hcjMSrvh65
         P49pUrM1ScCpVYohMKsxrF5xQhDWmG2KVzCgXU5q2qifGsBwxetKIcoQWlTi+Tsx7f9r
         7lIw==
X-Gm-Message-State: AOAM532eFm7T43UFIA66PAyq3Zov5JE/0SnSpmLPML2l3FrlGLcCrk4V
	DAbl+coU0r9ZgTVV+1GTFik=
X-Google-Smtp-Source: ABdhPJx0DBNL13NPa3deeNViSoiKN1+V/mSokbHBqKOCvwB4wHEGfXCHN4hU4LJO9efgOCEfd57w9g==
X-Received: by 2002:a6b:bc82:: with SMTP id m124mr17691838iof.172.1599486082768;
        Mon, 07 Sep 2020 06:41:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:290a:: with SMTP id l10ls4067800ilg.6.gmail; Mon, 07 Sep
 2020 06:41:22 -0700 (PDT)
X-Received: by 2002:a92:6906:: with SMTP id e6mr18728745ilc.249.1599486082391;
        Mon, 07 Sep 2020 06:41:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486082; cv=none;
        d=google.com; s=arc-20160816;
        b=P3sLGKfRH3M49itcFOLZYi6ldI7xmjEm8CCSwAg1fCMvVaQ0SJ24f+YLiy8NmVeDvy
         Cyh21KtQZKWofzBp+15DzL6N1t0MafSO3CULCfOl+x3DkgzNoRRp85JFm31PpHfyrX8n
         wFx84b2QQP6JWwBY5dhoJc5tIOooWr0pe7c8wxyb75oYQ0QqFepdPLVc5KLMCQnnWvHC
         ouDpFiti8n2/EympRcrLg7moq9Pcr7tbnQonHKR4riM2Z6FTOEKgAZdh3j/tOFxzbCqF
         WHlhejICNUzPifw9cWIXNCzDGnMujRmYujATvHPAdv1h86JCKFzzXrwELi2mypvj0RYV
         jUoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=8YnpSBDwpao87/ZVYJ4onx0/hDOUzOcPQWJ5jPR3XSc=;
        b=CGSkdJ6NrE38gyzZ/mvjt0qZ/Kk295lNXFmUDDLDGQssR/N1yokZcYjMPqY4HpVDA6
         iwk3Gd4iNEChDZI+2+oV94ZamWBvy41DRdbHWBy1+jqawtrTbYwRDyqcu5WMzM9Kgro7
         el8q6FXuqx/1wQVW2oO7vdEVKHmkssTcjSPH+24KZ2mEKbjnLV5oOLSOZhkl5YpravFg
         TbVn+YzPfXm1msHdZsp2eV2otuwOBP6bHeWtJtR3bwTi7w8m35vLzX8bH1KQu1szidOx
         BBCxNI6eQjo6C0eNpC0UEfjkuwSPyIePdBpn+hgorxQuAyegM0k7JoyFDAl3KgbCCBVx
         ciOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KvR1k1HI;
       spf=pass (google.com: domain of 3gthwxwukcuwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3gThWXwUKCUwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id a13si108889ios.2.2020.09.07.06.41.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gthwxwukcuwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id a16so312788qtj.7
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:22 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a05:6214:292:: with SMTP id
 l18mr18806154qvv.3.1599486081663; Mon, 07 Sep 2020 06:41:21 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:50 +0200
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Message-Id: <20200907134055.2878499-6-elver@google.com>
Mime-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 05/10] mm, kfence: insert KFENCE hooks for SLUB
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KvR1k1HI;       spf=pass
 (google.com: domain of 3gthwxwukcuwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3gThWXwUKCUwsz9s5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--elver.bounces.google.com;
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

Inserts KFENCE hooks into the SLUB allocator.

We note the addition of the 'orig_size' argument to slab_alloc*()
functions, to be able to pass the originally requested size to KFENCE.
When KFENCE is disabled, there is no additional overhead, since these
functions are __always_inline.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/slub.c | 72 ++++++++++++++++++++++++++++++++++++++++---------------
 1 file changed, 53 insertions(+), 19 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index d4177aecedf6..5c5a13a7857c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -27,6 +27,7 @@
 #include <linux/ctype.h>
 #include <linux/debugobjects.h>
 #include <linux/kallsyms.h>
+#include <linux/kfence.h>
 #include <linux/memory.h>
 #include <linux/math64.h>
 #include <linux/fault-inject.h>
@@ -1557,6 +1558,11 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 	void *old_tail = *tail ? *tail : *head;
 	int rsize;
 
+	if (is_kfence_address(next)) {
+		slab_free_hook(s, next);
+		return true;
+	}
+
 	/* Head and tail of the reconstructed freelist */
 	*head = NULL;
 	*tail = NULL;
@@ -2660,7 +2666,8 @@ static inline void *get_freelist(struct kmem_cache *s, struct page *page)
  * already disabled (which is the case for bulk allocation).
  */
 static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
-			  unsigned long addr, struct kmem_cache_cpu *c)
+			  unsigned long addr, struct kmem_cache_cpu *c,
+			  size_t orig_size)
 {
 	void *freelist;
 	struct page *page;
@@ -2763,7 +2770,8 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
  * cpu changes by refetching the per cpu area pointer.
  */
 static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
-			  unsigned long addr, struct kmem_cache_cpu *c)
+			  unsigned long addr, struct kmem_cache_cpu *c,
+			  size_t orig_size)
 {
 	void *p;
 	unsigned long flags;
@@ -2778,7 +2786,7 @@ static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
 	c = this_cpu_ptr(s->cpu_slab);
 #endif
 
-	p = ___slab_alloc(s, gfpflags, node, addr, c);
+	p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
 	local_irq_restore(flags);
 	return p;
 }
@@ -2805,7 +2813,7 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
  * Otherwise we can simply pick the next object from the lockless free list.
  */
 static __always_inline void *slab_alloc_node(struct kmem_cache *s,
-		gfp_t gfpflags, int node, unsigned long addr)
+		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
 {
 	void *object;
 	struct kmem_cache_cpu *c;
@@ -2816,6 +2824,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	s = slab_pre_alloc_hook(s, &objcg, 1, gfpflags);
 	if (!s)
 		return NULL;
+
+	object = kfence_alloc(s, orig_size, gfpflags);
+	if (unlikely(object))
+		goto out;
+
 redo:
 	/*
 	 * Must read kmem_cache cpu data via this cpu ptr. Preemption is
@@ -2853,7 +2866,7 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	object = c->freelist;
 	page = c->page;
 	if (unlikely(!object || !node_match(page, node))) {
-		object = __slab_alloc(s, gfpflags, node, addr, c);
+		object = __slab_alloc(s, gfpflags, node, addr, c, orig_size);
 		stat(s, ALLOC_SLOWPATH);
 	} else {
 		void *next_object = get_freepointer_safe(s, object);
@@ -2889,20 +2902,21 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
 	if (unlikely(slab_want_init_on_alloc(gfpflags, s)) && object)
 		memset(object, 0, s->object_size);
 
+out:
 	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object);
 
 	return object;
 }
 
 static __always_inline void *slab_alloc(struct kmem_cache *s,
-		gfp_t gfpflags, unsigned long addr)
+		gfp_t gfpflags, unsigned long addr, size_t orig_size)
 {
-	return slab_alloc_node(s, gfpflags, NUMA_NO_NODE, addr);
+	return slab_alloc_node(s, gfpflags, NUMA_NO_NODE, addr, orig_size);
 }
 
 void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
 {
-	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
+	void *ret = slab_alloc(s, gfpflags, _RET_IP_, s->object_size);
 
 	trace_kmem_cache_alloc(_RET_IP_, ret, s->object_size,
 				s->size, gfpflags);
@@ -2914,7 +2928,7 @@ EXPORT_SYMBOL(kmem_cache_alloc);
 #ifdef CONFIG_TRACING
 void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 {
-	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
+	void *ret = slab_alloc(s, gfpflags, _RET_IP_, size);
 	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags);
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
@@ -2925,7 +2939,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
 #ifdef CONFIG_NUMA
 void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
-	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);
+	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_, s->object_size);
 
 	trace_kmem_cache_alloc_node(_RET_IP_, ret,
 				    s->object_size, s->size, gfpflags, node);
@@ -2939,7 +2953,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *s,
 				    gfp_t gfpflags,
 				    int node, size_t size)
 {
-	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);
+	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_, size);
 
 	trace_kmalloc_node(_RET_IP_, ret,
 			   size, s->size, gfpflags, node);
@@ -2973,6 +2987,9 @@ static void __slab_free(struct kmem_cache *s, struct page *page,
 
 	stat(s, FREE_SLOWPATH);
 
+	if (kfence_free(head))
+		return;
+
 	if (kmem_cache_debug(s) &&
 	    !free_debug_processing(s, page, head, tail, cnt, addr))
 		return;
@@ -3216,6 +3233,13 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
 		df->s = cache_from_obj(s, object); /* Support for memcg */
 	}
 
+	if (is_kfence_address(object)) {
+		slab_free_hook(df->s, object);
+		WARN_ON(!kfence_free(object));
+		p[size] = NULL; /* mark object processed */
+		return size;
+	}
+
 	/* Start new detached freelist */
 	df->page = page;
 	set_freepointer(df->s, object, NULL);
@@ -3290,8 +3314,14 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	c = this_cpu_ptr(s->cpu_slab);
 
 	for (i = 0; i < size; i++) {
-		void *object = c->freelist;
+		void *object = kfence_alloc(s, s->object_size, flags);
 
+		if (unlikely(object)) {
+			p[i] = object;
+			continue;
+		}
+
+		object = c->freelist;
 		if (unlikely(!object)) {
 			/*
 			 * We may have removed an object from c->freelist using
@@ -3307,7 +3337,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 			 * of re-populating per CPU c->freelist
 			 */
 			p[i] = ___slab_alloc(s, flags, NUMA_NO_NODE,
-					    _RET_IP_, c);
+					    _RET_IP_, c, size);
 			if (unlikely(!p[i]))
 				goto error;
 
@@ -3962,7 +3992,7 @@ void *__kmalloc(size_t size, gfp_t flags)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc(s, flags, _RET_IP_);
+	ret = slab_alloc(s, flags, _RET_IP_, size);
 
 	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);
 
@@ -4010,7 +4040,7 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc_node(s, flags, node, _RET_IP_);
+	ret = slab_alloc_node(s, flags, node, _RET_IP_, size);
 
 	trace_kmalloc_node(_RET_IP_, ret, size, s->size, flags, node);
 
@@ -4036,6 +4066,7 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 	struct kmem_cache *s;
 	unsigned int offset;
 	size_t object_size;
+	bool is_kfence = is_kfence_address(ptr);
 
 	ptr = kasan_reset_tag(ptr);
 
@@ -4048,10 +4079,13 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 			       to_user, 0, n);
 
 	/* Find offset within object. */
-	offset = (ptr - page_address(page)) % s->size;
+	if (is_kfence)
+		offset = ptr - kfence_object_start(ptr);
+	else
+		offset = (ptr - page_address(page)) % s->size;
 
 	/* Adjust for redzone and reject if within the redzone. */
-	if (kmem_cache_debug_flags(s, SLAB_RED_ZONE)) {
+	if (!is_kfence && kmem_cache_debug_flags(s, SLAB_RED_ZONE)) {
 		if (offset < s->red_left_pad)
 			usercopy_abort("SLUB object in left red zone",
 				       s->name, to_user, offset, n);
@@ -4460,7 +4494,7 @@ void *__kmalloc_track_caller(size_t size, gfp_t gfpflags, unsigned long caller)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc(s, gfpflags, caller);
+	ret = slab_alloc(s, gfpflags, caller, size);
 
 	/* Honor the call site pointer we received. */
 	trace_kmalloc(caller, ret, size, s->size, gfpflags);
@@ -4491,7 +4525,7 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t gfpflags,
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc_node(s, gfpflags, node, caller);
+	ret = slab_alloc_node(s, gfpflags, node, caller, size);
 
 	/* Honor the call site pointer we received. */
 	trace_kmalloc_node(caller, ret, size, s->size, gfpflags, node);
-- 
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-6-elver%40google.com.
