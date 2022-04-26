Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEWDUCJQMGQEE5ODCAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id D32985103F2
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:06 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id h65-20020a1c2144000000b0038e9ce3b29csf1495967wmh.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991506; cv=pass;
        d=google.com; s=arc-20160816;
        b=s7e1KVH+801zRJsmUGtOxh+4Ck/yS2O3Bkmuw+Ey2K+ellqkFMbrsvcmjqd66uQCFO
         DynExmW8TRJUR3HikWwb/CLL5eC8gojZyACgWYjz8o+8xjWD3WoKh6TD4Qu82y6yGlXj
         CZ/MkUPDTkr+5wciROqbAck4bTCmpgiZFS3MNcbQcQ4eBQMSZpoJyhWDiy/5bursPUaa
         T1SGwYfiFAdsePv6hL9R4wzvmN9guttllJ2NaoQs5NRy9Km+OnIF1h61c5Maw7CnEh8S
         Qpuzhay5s7HoCwWQyW67ufI+OmCgwvLhh7YxoC675pI3+4ZuZPN5eOqJi2Uy57u8ZDi2
         fFqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oYrWSJ45iAhMhzjxA5QIFb+JFIcYaJJJqbpYq3dbp/E=;
        b=FHIlkt8rEPoU0va6msK623sCBLwlGu3W83Py5xbaZMyFjVOaN43W0XSqMXJGIKfpaC
         mNETSFF6jCNs39QvC/mXJyb/lusvHw1lZSch182cuzzNWvcaYSvDH65+QF3dd841briH
         Wleiu3E3IHK5w1/qNTaZ9jV4Kp7DrioThGNzQCP4FT5VFbTf6hmoIX4IHUgk8RGabYlF
         a8dhHV2HK6J4jEz7c3ffyAhZdBOdSPALVCuQJnvaT6HkhQQUOkFDIwfpZZtroMYGrkmz
         MbLRVvc2pam/rgntxTHzeLBtD0slF5VxWix3aMuj94shO2r6Lw9HYtvzSPm7DLzxAErg
         +iAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YzWXjysg;
       spf=pass (google.com: domain of 3kcfoygykcy0x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kCFoYgYKCY0x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oYrWSJ45iAhMhzjxA5QIFb+JFIcYaJJJqbpYq3dbp/E=;
        b=m2iHZd5YRF3Htxw17lv9Ooz6ckPUq9VDO+W6js1XqLt0w7oVI9gHrVf+3ovEuiTlli
         asbhZysjv7w6voupiTtD8UFfYvjc4Nfs09vraB5GOnSGm1enZ5sj/tU/QiZ/vW2dUtLl
         OsBryX9fTJhfXMgMEDpY/4TxVE/bxbEGwpbMn0QMu+A/9wHtzZD4nzc/29iZ+NHnsoWN
         BLIuyCxSRudktJVMgA7lytZmEJ4bQjrI9EPu7Jd+F0fRMamxXFYLSMK/Q63KAhtijPCm
         navrZTxXg28jjxAX0zUHKwMn6fE2EPe6HF/VbX3O6Iymuv+PTOedz1Sk9k2OQF68xdmX
         bwZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oYrWSJ45iAhMhzjxA5QIFb+JFIcYaJJJqbpYq3dbp/E=;
        b=2AFbZqntAlhtMbSiZG7puJOQ4rO6WC4rZvZszpKJssvuiL/656cXlkaqjauLiCzuEM
         bnX0A/xP2iG5bpNhz8uX3kS4M9CVrqCAdSoX8YXhsPwrThwx3vlRCOtaTLlpKXox9871
         gNZkCUndYOhQyEwoRK/E5PXpNEbBGmZVwTxRCav9pS7jtwVTAF2Cz2Gq2FhY9Zc1KIMT
         QTidGCwP/DRLohXb5pGqP8+JsKqSLbgZkYRvDY2c7xz4oVEXExddkfvfUv4/+3LbNIVX
         v77x72Ep4L+CBklC+aPe6xzDeDcM+XZXx8Tsfsqlwe5djpZkaEcAbQoHNe+nkiLHIfQc
         00ew==
X-Gm-Message-State: AOAM5322cHA40D+h46DBuCeljCHnRh3b3CErY2CHyu4riFrQR0mn9fNt
	PJUEslDnTOfqlk8PDBpRBqU=
X-Google-Smtp-Source: ABdhPJz1xTNrp4nsvpA8YgPUiCbveYJB5dlX83rjmHcKg3sl/qJcg3ETLYjkXWQOHvq2ISy8o/M/Tw==
X-Received: by 2002:a05:600c:4f89:b0:392:8959:f8e7 with SMTP id n9-20020a05600c4f8900b003928959f8e7mr31092474wmq.164.1650991506601;
        Tue, 26 Apr 2022 09:45:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1447:b0:20a:dc13:2578 with SMTP id
 v7-20020a056000144700b0020adc132578ls1003913wrx.1.gmail; Tue, 26 Apr 2022
 09:45:05 -0700 (PDT)
X-Received: by 2002:adf:f84b:0:b0:20a:ece0:905e with SMTP id d11-20020adff84b000000b0020aece0905emr93756wrq.323.1650991505529;
        Tue, 26 Apr 2022 09:45:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991505; cv=none;
        d=google.com; s=arc-20160816;
        b=ZHwF2ZJxj4pYypgmukb8yixxLxE++z8aoA+pUqrswn1KPnrMWhkAatxT+oMugfaEw1
         Xx7TJ1FNTA3/4nUL3fzhrgnwWcc3CHrRcPjE/qbnB1lfGTSgxtcGOKbVzjpJLMOyoBt6
         Tn9jn3ewWDpvDlQU/VGV0TfcbIwlV+BfNTcdFXeI0neqCRZH7YXcfwjVnlEeFm87oVZi
         jydWIZJY7P1PwSiczKzI7EIUyjG82Sopja+6Z66gfzXlHV+YComfX6qRRIwa35J7yHKE
         YLy9l6X2mOwDp5cB00wlhoIUiW00MCAR3rP54GhrYcEwO6Iw0dPFZQ7RXZEX3Sbg8TAB
         4QjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mDlUedrAZbNWp5ky59jIg6dQAqQa/OsCzADtdk11998=;
        b=O7FxnZrTOzZx5bEM9InaOp2T43tqnhguddHZ3w94iqjsqWWL1DkA7F/Ze9r/fyJYSb
         tdysVX+sDsGA9PqlQUgHUq2dHti9WAFnQEkp+Kx9lGupFwtvB8kwvnzigglibsdnp5oc
         LUOwoTqhvSvIx14t7LeB+pgvDNHsXiUEszcvScvQeDoUzzaeOsQ4eJ7Ol01nOpSDawN7
         UPVl/Usar52xXUo8gaViikufrzTBjiYu1SlMXWZVlDQBke16PVfpeLvDdL/7lMiHiaqZ
         yKIV0if34wI6CZ6KBCj2xbyywrGdQRwhGkLAnB9mbiwWVAVEMPWfBc99SS8/2nN+UiMZ
         kKIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YzWXjysg;
       spf=pass (google.com: domain of 3kcfoygykcy0x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kCFoYgYKCY0x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id l19-20020a05600c1d1300b00393e80e70c9si115682wms.1.2022.04.26.09.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kcfoygykcy0x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id l24-20020a056402231800b00410f19a3103so10611194eda.5
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:05 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:5114:b0:423:f33d:b3c with SMTP id
 m20-20020a056402511400b00423f33d0b3cmr25558297edd.199.1650991504954; Tue, 26
 Apr 2022 09:45:04 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:46 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-18-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 17/46] kmsan: mm: call KMSAN hooks from SLUB code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YzWXjysg;       spf=pass
 (google.com: domain of 3kcfoygykcy0x2zuv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3kCFoYgYKCY0x2zuv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

In order to report uninitialized memory coming from heap allocations
KMSAN has to poison them unless they're created with __GFP_ZERO.

It's handy that we need KMSAN hooks in the places where
init_on_alloc/init_on_free initialization is performed.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- move the implementation of SLUB hooks here

Link: https://linux-review.googlesource.com/id/I6954b386c5c5d7f99f48bb6cbcc74b75136ce86e
---
 include/linux/kmsan.h | 57 ++++++++++++++++++++++++++++++
 mm/kmsan/hooks.c      | 80 +++++++++++++++++++++++++++++++++++++++++++
 mm/slab.h             |  1 +
 mm/slub.c             | 21 ++++++++++--
 4 files changed, 157 insertions(+), 2 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index da41850b46cbd..ed3630068e2ef 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -16,6 +16,7 @@
 #include <linux/vmalloc.h>
 
 struct page;
+struct kmem_cache;
 
 #ifdef CONFIG_KMSAN
 
@@ -73,6 +74,44 @@ void kmsan_free_page(struct page *page, unsigned int order);
  */
 void kmsan_copy_page_meta(struct page *dst, struct page *src);
 
+/**
+ * kmsan_slab_alloc() - Notify KMSAN about a slab allocation.
+ * @s:      slab cache the object belongs to.
+ * @object: object pointer.
+ * @flags:  GFP flags passed to the allocator.
+ *
+ * Depending on cache flags and GFP flags, KMSAN sets up the metadata of the
+ * newly created object, marking it as initialized or uninitialized.
+ */
+void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags);
+
+/**
+ * kmsan_slab_free() - Notify KMSAN about a slab deallocation.
+ * @s:      slab cache the object belongs to.
+ * @object: object pointer.
+ *
+ * KMSAN marks the freed object as uninitialized.
+ */
+void kmsan_slab_free(struct kmem_cache *s, void *object);
+
+/**
+ * kmsan_kmalloc_large() - Notify KMSAN about a large slab allocation.
+ * @ptr:   object pointer.
+ * @size:  object size.
+ * @flags: GFP flags passed to the allocator.
+ *
+ * Similar to kmsan_slab_alloc(), but for large allocations.
+ */
+void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags);
+
+/**
+ * kmsan_kfree_large() - Notify KMSAN about a large slab deallocation.
+ * @ptr: object pointer.
+ *
+ * Similar to kmsan_slab_free(), but for large allocations.
+ */
+void kmsan_kfree_large(const void *ptr);
+
 /**
  * kmsan_map_kernel_range_noflush() - Notify KMSAN about a vmap.
  * @start:	start of vmapped range.
@@ -139,6 +178,24 @@ static inline void kmsan_copy_page_meta(struct page *dst, struct page *src)
 {
 }
 
+static inline void kmsan_slab_alloc(struct kmem_cache *s, void *object,
+				    gfp_t flags)
+{
+}
+
+static inline void kmsan_slab_free(struct kmem_cache *s, void *object)
+{
+}
+
+static inline void kmsan_kmalloc_large(const void *ptr, size_t size,
+				       gfp_t flags)
+{
+}
+
+static inline void kmsan_kfree_large(const void *ptr)
+{
+}
+
 static inline void kmsan_vmap_pages_range_noflush(unsigned long start,
 						  unsigned long end,
 						  pgprot_t prot,
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 070756be70e3a..052e17b7a717d 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -26,6 +26,86 @@
  * skipping effects of functions like memset() inside instrumented code.
  */
 
+void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
+{
+	if (unlikely(object == NULL))
+		return;
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	/*
+	 * There's a ctor or this is an RCU cache - do nothing. The memory
+	 * status hasn't changed since last use.
+	 */
+	if (s->ctor || (s->flags & SLAB_TYPESAFE_BY_RCU))
+		return;
+
+	kmsan_enter_runtime();
+	if (flags & __GFP_ZERO)
+		kmsan_internal_unpoison_memory(object, s->object_size,
+					       KMSAN_POISON_CHECK);
+	else
+		kmsan_internal_poison_memory(object, s->object_size, flags,
+					     KMSAN_POISON_CHECK);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_slab_alloc);
+
+void kmsan_slab_free(struct kmem_cache *s, void *object)
+{
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+
+	/* RCU slabs could be legally used after free within the RCU period */
+	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
+		return;
+	/*
+	 * If there's a constructor, freed memory must remain in the same state
+	 * until the next allocation. We cannot save its state to detect
+	 * use-after-free bugs, instead we just keep it unpoisoned.
+	 */
+	if (s->ctor)
+		return;
+	kmsan_enter_runtime();
+	kmsan_internal_poison_memory(object, s->object_size, GFP_KERNEL,
+				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_slab_free);
+
+void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
+{
+	if (unlikely(ptr == NULL))
+		return;
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	kmsan_enter_runtime();
+	if (flags & __GFP_ZERO)
+		kmsan_internal_unpoison_memory((void *)ptr, size,
+					       /*checked*/ true);
+	else
+		kmsan_internal_poison_memory((void *)ptr, size, flags,
+					     KMSAN_POISON_CHECK);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_kmalloc_large);
+
+void kmsan_kfree_large(const void *ptr)
+{
+	struct page *page;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	kmsan_enter_runtime();
+	page = virt_to_head_page((void *)ptr);
+	KMSAN_WARN_ON(ptr != page_address(page));
+	kmsan_internal_poison_memory((void *)ptr,
+				     PAGE_SIZE << compound_order(page),
+				     GFP_KERNEL,
+				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
+	kmsan_leave_runtime();
+}
+EXPORT_SYMBOL(kmsan_kfree_large);
+
 static unsigned long vmalloc_shadow(unsigned long addr)
 {
 	return (unsigned long)kmsan_get_metadata((void *)addr,
diff --git a/mm/slab.h b/mm/slab.h
index 95eb34174c1bb..1276b83656091 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -751,6 +751,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 			memset(p[i], 0, s->object_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
+		kmsan_slab_alloc(s, p[i], flags);
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
diff --git a/mm/slub.c b/mm/slub.c
index ed5c2c03a47aa..45082acaa6739 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -22,6 +22,7 @@
 #include <linux/proc_fs.h>
 #include <linux/seq_file.h>
 #include <linux/kasan.h>
+#include <linux/kmsan.h>
 #include <linux/cpu.h>
 #include <linux/cpuset.h>
 #include <linux/mempolicy.h>
@@ -357,18 +358,28 @@ static void prefetch_freepointer(const struct kmem_cache *s, void *object)
 	prefetchw(object + s->offset);
 }
 
+/*
+ * When running under KMSAN, get_freepointer_safe() may return an uninitialized
+ * pointer value in the case the current thread loses the race for the next
+ * memory chunk in the freelist. In that case this_cpu_cmpxchg_double() in
+ * slab_alloc_node() will fail, so the uninitialized value won't be used, but
+ * KMSAN will still check all arguments of cmpxchg because of imperfect
+ * handling of inline assembly.
+ * To work around this problem, use kmsan_init() to force initialize the
+ * return value of get_freepointer_safe().
+ */
 static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
 {
 	unsigned long freepointer_addr;
 	void *p;
 
 	if (!debug_pagealloc_enabled_static())
-		return get_freepointer(s, object);
+		return kmsan_init(get_freepointer(s, object));
 
 	object = kasan_reset_tag(object);
 	freepointer_addr = (unsigned long)object + s->offset;
 	copy_from_kernel_nofault(&p, (void **)freepointer_addr, sizeof(p));
-	return freelist_ptr(s, p, freepointer_addr);
+	return kmsan_init(freelist_ptr(s, p, freepointer_addr));
 }
 
 static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
@@ -1683,6 +1694,7 @@ static inline void *kmalloc_large_node_hook(void *ptr, size_t size, gfp_t flags)
 	ptr = kasan_kmalloc_large(ptr, size, flags);
 	/* As ptr might get tagged, call kmemleak hook after KASAN. */
 	kmemleak_alloc(ptr, size, 1, flags);
+	kmsan_kmalloc_large(ptr, size, flags);
 	return ptr;
 }
 
@@ -1690,12 +1702,14 @@ static __always_inline void kfree_hook(void *x)
 {
 	kmemleak_free(x);
 	kasan_kfree_large(x);
+	kmsan_kfree_large(x);
 }
 
 static __always_inline bool slab_free_hook(struct kmem_cache *s,
 						void *x, bool init)
 {
 	kmemleak_free_recursive(x, s->flags);
+	kmsan_slab_free(s, x);
 
 	debug_check_no_locks_freed(x, s->object_size);
 
@@ -3730,6 +3744,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
 				slab_want_init_on_alloc(flags, s));
+
 	return i;
 error:
 	slub_put_cpu_ptr(s->cpu_slab);
@@ -5898,6 +5913,7 @@ static char *create_unique_id(struct kmem_cache *s)
 	p += sprintf(p, "%07u", s->size);
 
 	BUG_ON(p > name + ID_STR_LENGTH - 1);
+	kmsan_unpoison_memory(name, p - name);
 	return name;
 }
 
@@ -5999,6 +6015,7 @@ static int sysfs_slab_alias(struct kmem_cache *s, const char *name)
 	al->name = name;
 	al->next = alias_list;
 	alias_list = al;
+	kmsan_unpoison_memory(al, sizeof(struct saved_alias));
 	return 0;
 }
 
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-18-glider%40google.com.
