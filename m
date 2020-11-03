Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3VUQ36QKGQEC2EKDMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 804472A4DA7
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 18:59:11 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d6sf661874pfn.15
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 09:59:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604426350; cv=pass;
        d=google.com; s=arc-20160816;
        b=KG4taXfqPYjsWsg9QLZVqIf+tATUqTPlPBzZxp3PUWvC53yVglKf4bWOvFE78x2ZxT
         ZLIGykMbbKuf1w/QeltltESk8LiyQe6Slk+Iyv59G21UlC6YMy90l4i2AjOQ7qdNkscq
         weK653ChRIDyvgJMU72QM9NnWoHOQGpvAnGTQelWnXVnYdGu4/aDQqu5pdRSALvv8vp2
         hJrcCWuUwqESgTuASLS9Wz0UVilihiFTKHivUzcNnDy6HnuMjycsfjnzumramWJVciDU
         vaDakjvWpJoJYopMEXjw7XCi31z8KZ1RvEl4v+ZMDHER3IUugMyJuAdrofORX3SlV0Pt
         fsJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Ey61EkLheHkdjB1XNRSCdQk9lH3j9toG5jw6vfCkB3A=;
        b=xiJVtkRIMNiJzmy/nSUvQZNPkmrvtBFGvLABFO1YXTBLuo+VO9+aGjcRKFg6/hMOaR
         ol5qaphgwmMa+ZBwkTPrn2r8Hauy7dnDJBlxGR9XuO80cOqU2GXTJS/z2Ueuu2n5keVH
         8RNYQKTPOwvD8V2qBeR73P0N04YwWchg01Ymx/P0tzVn9Ifw9CKXjSvI4OL91Cxrj0wD
         BRHlKSKVxcxoKIawPkPVWkb62/rX4PldIHL+AUFYu+uSosoMAWSuC/PGGmQpJa3gXV7o
         l70Nr36eqaJzoX98rlntEmW5nt/049VFDaOWnazPnMs1OPaxGMKNSL4FW5jo6jXlFfpl
         aQVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dwz6Vbt8;
       spf=pass (google.com: domain of 3bjqhxwukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bJqhXwUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ey61EkLheHkdjB1XNRSCdQk9lH3j9toG5jw6vfCkB3A=;
        b=UX7PXI+/gpbwO6S4o5ZYgMxG/OJXUMMQicI3TtBrKj4MWAGTEHtwXNVkkk9aWiUX3e
         IzWN9LTIk81B8FcFlTQkBQBWpUaPnxAmGWWuz2Yw38OJFkPyvz+Z2L1t5CY4Lyt2tQew
         HGELZTbkrI2U8tp9tauA3BAcnqengWpa0zxcRhMVaoo6PR5hAagBNp7PUX+xIgzOZQpT
         oVutf3X1DzeYAFUrmUqFzoB39IcxfQ9Ek6KyUP8M6hvgGfmsh21Pw6ksrQFb0fjfBjz3
         iDnEsuEgFJp+HG3sGN/S/j+FvVpp2UwKemJRs8De2WChgDPCx6z6Jn6zIhKXubxEMRbU
         eIuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ey61EkLheHkdjB1XNRSCdQk9lH3j9toG5jw6vfCkB3A=;
        b=A2y1O0ooGzedSLLT6Ujruqxq+GDqIuBqKUfwrqy/79BLhf65cDG0hi95R4xRkJh9NE
         2wl2oum70yFCevAqmzHpZfz/phFAGDNvXWNEvQs+s2tf5bMbjqLGx8j4f2N+v5QfPJHo
         tuJ3IJola2SJsIMorW8KqPiKgrQLk35KZDJxJzL+QnnPUQQYpayczfcJ+g7HPhRLhIds
         1+apb7O57z9Qlo5wZXHowHDH2FYSmXaK/5Oprf92k1nJxHLpNjmfU69SamGR0u3mWnP3
         hcT3qQelVXmcFx2sC3zjuJ5E6Er5WKuscJLNZCEgWjzKE+vxjamztWKve6H6ktLfw/Hm
         Xgzw==
X-Gm-Message-State: AOAM531GSPU+Z4JHmPa6/JhhCLbSH3JzjbHybsPVeWx17YaCWnvzoZOJ
	0X7XJcA95zc4roqV/jnf5NE=
X-Google-Smtp-Source: ABdhPJw+FLnphwyVpzMZoKQv6ROBBES5BL+om5NAJrcsj4uUtbwsyAfvcN5PdgNhy1fbglbaEgQh/w==
X-Received: by 2002:a17:902:d706:b029:d6:c71c:2599 with SMTP id w6-20020a170902d706b02900d6c71c2599mr11350989ply.46.1604426350149;
        Tue, 03 Nov 2020 09:59:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:231e:: with SMTP id j30ls886269pgj.1.gmail; Tue, 03 Nov
 2020 09:59:09 -0800 (PST)
X-Received: by 2002:a63:cc12:: with SMTP id x18mr18465609pgf.262.1604426349487;
        Tue, 03 Nov 2020 09:59:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604426349; cv=none;
        d=google.com; s=arc-20160816;
        b=GQ1/UgZrSPjO4q6BgzFNgOpJkQeB2d5+8mE/Wcb6+FjLX1u9zj4eVPOgeWIXPI4is8
         TYLVsiTdtKkPUH2Woge//0aoAPA5fMVDcK6zqgyXl0JHISd/IwgROrKo2blKie0IJ8/Q
         IfhLwiTIQBLdJ8G7WKKT8UN/Du3D/csvAs8YqJHOp8mqqnap3RcwqK7/uoHJrS63VvqQ
         jvMWoaoWbktfIgrIH7sveQ+VZaWKu/fBhFUhdzzDyLN9ZJO8bb4ChuQd8RZ6Qa/axbim
         O0f6zMt7KuR08HenWYMb8ppGdqG7t7N8EYz3iQYasNux+1vxyBr24jPoG5HnYdtuZHP+
         /OPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=G0Sh650oHkforl26PXMO/X+HZUi2ibltrnsBpzPVls4=;
        b=S+ysGGfi0UdzK0KZRV//1iBPMHhh2A/DsfNC5U1kMS3X3rVIT1b90IbsOT0OzIgCM4
         hypFTaPYXTBuCo4TfDJt8gD3zMXKPRueiqEKWwpKJ7WhDCdq2Zhndch0dKN4GJWbwEEa
         Ej5AV0XxzVbA1yNYq9o7cJ0uOnVjEw5KWokUPFwHMxftpS4meKebdqpYGxLRGdWU/Ss7
         QWbHld9nqS4OCrN12Vx7fM2a8Y99H9Y7JeJtb0ldZ73vuF/GjkENDxp3dolpr0laU0/b
         lt5m2/y8IXjv2i6R2Iqt5/wvNV9FajyKhcmqas82mBOGox77AdPlChCW1Nss9YTH6d1Z
         cPsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dwz6Vbt8;
       spf=pass (google.com: domain of 3bjqhxwukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bJqhXwUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h17si326808pjv.3.2020.11.03.09.59.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 09:59:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bjqhxwukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id f126so11233644qke.17
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 09:59:09 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:b610:: with SMTP id f16mr28390524qve.36.1604426348447;
 Tue, 03 Nov 2020 09:59:08 -0800 (PST)
Date: Tue,  3 Nov 2020 18:58:37 +0100
In-Reply-To: <20201103175841.3495947-1-elver@google.com>
Message-Id: <20201103175841.3495947-6-elver@google.com>
Mime-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 5/9] mm, kfence: insert KFENCE hooks for SLUB
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
 header.i=@google.com header.s=20161025 header.b=Dwz6Vbt8;       spf=pass
 (google.com: domain of 3bjqhxwukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3bJqhXwUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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
Reviewed-by: Jann Horn <jannh@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v7:
* Revert unused orig_size [reported by Jann Horn].
* Add Jann's Reviewed-by.
* Use __kfence_free() where we know is_kfence_address() is true.
* Re-add SLUB-specific code setting page->objects.

v5:
* Fix obj_to_index for kfence objects.

v3:
* Rewrite patch description to clarify need for 'orig_size'
  [reported by Christopher Lameter].
---
 include/linux/slub_def.h |  3 ++
 mm/kfence/core.c         |  2 ++
 mm/slub.c                | 60 ++++++++++++++++++++++++++++++----------
 3 files changed, 51 insertions(+), 14 deletions(-)

diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index 1be0ed5befa1..dcde82a4434c 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -7,6 +7,7 @@
  *
  * (C) 2007 SGI, Christoph Lameter
  */
+#include <linux/kfence.h>
 #include <linux/kobject.h>
 #include <linux/reciprocal_div.h>
 
@@ -185,6 +186,8 @@ static inline unsigned int __obj_to_index(const struct kmem_cache *cache,
 static inline unsigned int obj_to_index(const struct kmem_cache *cache,
 					const struct page *page, void *obj)
 {
+	if (is_kfence_address(obj))
+		return 0;
 	return __obj_to_index(cache, page_address(page), obj);
 }
 
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 721fd6318c91..9d597013cd5d 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -313,6 +313,8 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Set required struct page fields. */
 	page = virt_to_page(meta->addr);
 	page->slab_cache = cache;
+	if (IS_ENABLED(CONFIG_SLUB))
+		page->objects = 1;
 	if (IS_ENABLED(CONFIG_SLAB))
 		page->s_mem = addr;
 
diff --git a/mm/slub.c b/mm/slub.c
index b30be2385d1c..c15998718ea5 100644
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
@@ -1553,6 +1554,11 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
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
@@ -2805,7 +2811,7 @@ static __always_inline void maybe_wipe_obj_freeptr(struct kmem_cache *s,
  * Otherwise we can simply pick the next object from the lockless free list.
  */
 static __always_inline void *slab_alloc_node(struct kmem_cache *s,
-		gfp_t gfpflags, int node, unsigned long addr)
+		gfp_t gfpflags, int node, unsigned long addr, size_t orig_size)
 {
 	void *object;
 	struct kmem_cache_cpu *c;
@@ -2816,6 +2822,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
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
@@ -2888,20 +2899,21 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s,
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
@@ -2913,7 +2925,7 @@ EXPORT_SYMBOL(kmem_cache_alloc);
 #ifdef CONFIG_TRACING
 void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 {
-	void *ret = slab_alloc(s, gfpflags, _RET_IP_);
+	void *ret = slab_alloc(s, gfpflags, _RET_IP_, size);
 	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags);
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
@@ -2924,7 +2936,7 @@ EXPORT_SYMBOL(kmem_cache_alloc_trace);
 #ifdef CONFIG_NUMA
 void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
 {
-	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);
+	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_, s->object_size);
 
 	trace_kmem_cache_alloc_node(_RET_IP_, ret,
 				    s->object_size, s->size, gfpflags, node);
@@ -2938,7 +2950,7 @@ void *kmem_cache_alloc_node_trace(struct kmem_cache *s,
 				    gfp_t gfpflags,
 				    int node, size_t size)
 {
-	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_);
+	void *ret = slab_alloc_node(s, gfpflags, node, _RET_IP_, size);
 
 	trace_kmalloc_node(_RET_IP_, ret,
 			   size, s->size, gfpflags, node);
@@ -2972,6 +2984,9 @@ static void __slab_free(struct kmem_cache *s, struct page *page,
 
 	stat(s, FREE_SLOWPATH);
 
+	if (kfence_free(head))
+		return;
+
 	if (kmem_cache_debug(s) &&
 	    !free_debug_processing(s, page, head, tail, cnt, addr))
 		return;
@@ -3216,6 +3231,13 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
 		df->s = cache_from_obj(s, object); /* Support for memcg */
 	}
 
+	if (is_kfence_address(object)) {
+		slab_free_hook(df->s, object);
+		__kfence_free(object);
+		p[size] = NULL; /* mark object processed */
+		return size;
+	}
+
 	/* Start new detached freelist */
 	df->page = page;
 	set_freepointer(df->s, object, NULL);
@@ -3291,8 +3313,14 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
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
@@ -3963,7 +3991,7 @@ void *__kmalloc(size_t size, gfp_t flags)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc(s, flags, _RET_IP_);
+	ret = slab_alloc(s, flags, _RET_IP_, size);
 
 	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);
 
@@ -4011,7 +4039,7 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc_node(s, flags, node, _RET_IP_);
+	ret = slab_alloc_node(s, flags, node, _RET_IP_, size);
 
 	trace_kmalloc_node(_RET_IP_, ret, size, s->size, flags, node);
 
@@ -4037,6 +4065,7 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
 	struct kmem_cache *s;
 	unsigned int offset;
 	size_t object_size;
+	bool is_kfence = is_kfence_address(ptr);
 
 	ptr = kasan_reset_tag(ptr);
 
@@ -4049,10 +4078,13 @@ void __check_heap_object(const void *ptr, unsigned long n, struct page *page,
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
@@ -4461,7 +4493,7 @@ void *__kmalloc_track_caller(size_t size, gfp_t gfpflags, unsigned long caller)
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc(s, gfpflags, caller);
+	ret = slab_alloc(s, gfpflags, caller, size);
 
 	/* Honor the call site pointer we received. */
 	trace_kmalloc(caller, ret, size, s->size, gfpflags);
@@ -4492,7 +4524,7 @@ void *__kmalloc_node_track_caller(size_t size, gfp_t gfpflags,
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
 
-	ret = slab_alloc_node(s, gfpflags, node, caller);
+	ret = slab_alloc_node(s, gfpflags, node, caller, size);
 
 	/* Honor the call site pointer we received. */
 	trace_kmalloc_node(caller, ret, size, s->size, gfpflags, node);
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201103175841.3495947-6-elver%40google.com.
