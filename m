Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMX6RSMQMGQEZQGU5VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 77E255B9E0F
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:23 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id h23-20020a197017000000b004977813cd43sf5570989lfc.4
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254323; cv=pass;
        d=google.com; s=arc-20160816;
        b=y2tFkXWNnX9wmBvGsp4bUagZq8LQvE4F+KLxgtvP3WK424xfKk4JI5712URIvX6OQ7
         tweVoHpmqihyP9cxqlneZlBttgWGlH6CPwjIQ8aqx70Z62Jf4VmUuVl0ky5F+yAYNfTa
         3xVBwd/CRnbSvdPTIx/yWTAHRnhNfl8HXqJMOz5BCr/ow3Dt4DPKIg4z6ZE3JnrW6Cqo
         MlLzN55+CwUQwgDO8E+tJednO0qTUGdLgKm29KFFygVypfUgCxpF25EGfekzLSSc928S
         c4f3H1uHZhW18WovSMb1atO9GcKhmogjxQqBDQlXNPynBwH1ned0ZFRL2W2Q3eT5+0oi
         w4Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=YRGFXF849pqXMI0SXaZwzy9tQbqeAIpGj0+v4HY9pAU=;
        b=iCHFCiGYw4fMO6bMcB9QsQWirsnJWZTXOcThzX9wAbDv/+nT0FiLUL8yZ3KUe3aXKy
         UKJ45gBaEBuarDhtvl2pJnIXXTjdYtmTrUu7k9eYbo7hM74zh0MVXYwd8EkyjMuOB709
         ntnbOoXinpK1JHHqY5etg+DjJfn5Kt2LYfRNisd+zzTcjqV5TH+6fo7Qz14leDOU+qy5
         /xqnwrHTn/WPzY51nNXVr7AJSy/cDqHmrIWguKY1SdSuCKLWXRyMBIR2U2J5NDEu8MYz
         vH53odAcoXpNaD8MKse1kvTaUWzIv+KVKAMX3Qlsr1FeosWT9pMFf5PhNRVRbUqXHm7h
         E0fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fhAwNeFv;
       spf=pass (google.com: domain of 3lz8jywykcvo8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Lz8jYwYKCVo8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=YRGFXF849pqXMI0SXaZwzy9tQbqeAIpGj0+v4HY9pAU=;
        b=sca0Sns703Fqjvg5qBpS2A/ezefTtBMGRq4oVWLcekW9mDo6ei9coOl4ZuvtuI0o9F
         VJ3Dt9gCKz9Z9tq9+Qomm+ilZEGt8nQHoEd30yaQyaqqFOLgZrQAbUfPY+UCmkraWX3h
         IKXfEt+AxEQvcetgDAHPSjD8hCKy0oeDGVnHfzzT+uJEbexZySvxe5+s+BidBS0rBEPu
         UwDINFxXUZpYyFJdOXZh8WItgAtY1kUe/vAujXCVp+oCUkKmSzG9Ncfc6Qk4PXBxbRgS
         7EB2fJHnKFTqcVMk5fZhQewJjUhdmv586G8wICSx9LLMEEpE6uiMAiDp2JbfEZqogCgK
         JyNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=YRGFXF849pqXMI0SXaZwzy9tQbqeAIpGj0+v4HY9pAU=;
        b=iF3q1adIoxnWsFTFqtGDHcfM4DnyKdBLdztXSbYSIfGaKJnjSY6j8txznWe3IazQhg
         FwwSdVXWJoGzl6AujIKaa3hxD+XIGNtQ0920/XIC2EB6GqU9oPFHp1YrD9RHvUALpt9h
         Dqa9v4mZYhXrOQUgieBXPFDl7l53qzTF4MtPOoqYk+duveYXPHkhaqwiMUNyGJ7P2N6X
         zbHiPsZY+Y3wUcaI4LR5tQKPaLlwyTJSfvabXESfZOLnxIzLMhbFnlvOTUvbSOcqP4jd
         gGTsRAsxTRnLc5id+hhzStQohzLMESUCbN4uvQNFUdJQzbiIO5BzFU+T186x7nf6hnHS
         80UQ==
X-Gm-Message-State: ACrzQf1u86BGah/CqRaHlVbajikjWbSmeAaAEsWnJZglnIEORBoYon+j
	a+vq/P8IejlOqqLwD+ZcxMU=
X-Google-Smtp-Source: AMsMyM6ErGiPoMELmmk8JOflZY7DO2i1p+87qf1RgEzDlSk+nL7ZbjbaRbuwcUJjJiTrNKPUkIKxUg==
X-Received: by 2002:a2e:90d0:0:b0:26a:cd11:cb0e with SMTP id o16-20020a2e90d0000000b0026acd11cb0emr59074ljg.444.1663254322761;
        Thu, 15 Sep 2022 08:05:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e24:0:b0:49a:b814:856d with SMTP id o4-20020ac25e24000000b0049ab814856dls1227692lfg.1.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:05:20 -0700 (PDT)
X-Received: by 2002:a05:6512:3b22:b0:49a:d302:ae04 with SMTP id f34-20020a0565123b2200b0049ad302ae04mr136003lfv.72.1663254320256;
        Thu, 15 Sep 2022 08:05:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254320; cv=none;
        d=google.com; s=arc-20160816;
        b=I1IKbZMuwt9Kdvque05V3D1oqjJFxb6G08GQxPJnle0vrR/y2hbbRvjvDDmWzu/LAZ
         7hP+wGnViHy/4q6GFLlhWpnb5FTlOOBSRbdZC9Lg+6XfmOvoqRwCgDNTgReg1GOQLhfp
         4OBopFhLpgNOwf34q4A2WS75opM5cC0xU/bKunY8NslWwduqKRTdsCCYplG7j9zkBsbL
         Ltg8rHZT20ctRHWflyB7IY6GdtdrrzrZHUTHV+EoLZwfEVonSefW4gPRCNhdlR9xgLq1
         L/qV/YErpHkKx6einXlTWoxe/kiMRBu7C+Ty1gqORunZkwhTWTi7fZjeB8pIMMCDZLDl
         hYBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Ovg29tOGV0MBaJSgEZI8XqfnbTwhQ8WU6IE7DIFXMYM=;
        b=Z8sf7kFDWB0PB2l6musqvkCKv6MqwPZzhCQgZE5FNtjqqB13AI463p+1lvLwwT/XuB
         OoTsbgmcN8HxayDUwliQxQ010Qh2GdhoBLjU/Mmo6JnEAASe+UYNmb+j4Vg7zJHFppCW
         M7zYjpBN/dWS9OrMhX6jtmAUoXSnIoI4SHl51dd2v+LE6QcjQapj4MIKit6RmK5r+k9x
         +doF3BBAnAE8+xClQszAjE3LhBFugNsWNLnsedJHwxFVXH3YDXNzc3XSe5dkHC32yThr
         2ngaWUODKD4p0XF37RxrWflKGRUfC+snM2b2l2ya4GIijO5jx+sPwJF5qABXYtRIAXU3
         SC3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fhAwNeFv;
       spf=pass (google.com: domain of 3lz8jywykcvo8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Lz8jYwYKCVo8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a8-20020a056512200800b00498f2bdfdcdsi549598lfb.3.2022.09.15.08.05.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lz8jywykcvo8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id i27-20020adfaadb000000b0022a48b6436dso4336217wrc.23
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:20 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:adf:fac9:0:b0:228:652b:a33e with SMTP id
 a9-20020adffac9000000b00228652ba33emr61774wrs.61.1663254319665; Thu, 15 Sep
 2022 08:05:19 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:49 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-16-glider@google.com>
Subject: [PATCH v7 15/43] mm: kmsan: call KMSAN hooks from SLUB code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fhAwNeFv;       spf=pass
 (google.com: domain of 3lz8jywykcvo8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Lz8jYwYKCVo8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
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

In addition, we apply __no_kmsan_checks to get_freepointer_safe() to
suppress reports when accessing freelist pointers that reside in freed
objects.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v2:
 -- move the implementation of SLUB hooks here

v4:
 -- change sizeof(type) to sizeof(*ptr)
 -- swap mm: and kmsan: in the subject
 -- get rid of kmsan_init(), replace it with __no_kmsan_checks

v5:
 -- do not export KMSAN hooks that are not called from modules
 -- drop an unnecessary whitespace change

Link: https://linux-review.googlesource.com/id/I6954b386c5c5d7f99f48bb6cbcc74b75136ce86e
---
 include/linux/kmsan.h | 57 ++++++++++++++++++++++++++++++++
 mm/kmsan/hooks.c      | 76 +++++++++++++++++++++++++++++++++++++++++++
 mm/slab.h             |  1 +
 mm/slub.c             | 17 ++++++++++
 4 files changed, 151 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index b36bf3db835ee..5c4e0079054e6 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -14,6 +14,7 @@
 #include <linux/types.h>
 
 struct page;
+struct kmem_cache;
 
 #ifdef CONFIG_KMSAN
 
@@ -48,6 +49,44 @@ void kmsan_free_page(struct page *page, unsigned int order);
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
@@ -114,6 +153,24 @@ static inline void kmsan_copy_page_meta(struct page *dst, struct page *src)
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
index 040111bb9f6a3..000703c563a4d 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -27,6 +27,82 @@
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
+
 static unsigned long vmalloc_shadow(unsigned long addr)
 {
 	return (unsigned long)kmsan_get_metadata((void *)addr,
diff --git a/mm/slab.h b/mm/slab.h
index 4ec82bec15ecd..9d0afd2985df7 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -729,6 +729,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 			memset(p[i], 0, s->object_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
+		kmsan_slab_alloc(s, p[i], flags);
 	}
 
 	memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
diff --git a/mm/slub.c b/mm/slub.c
index 862dbd9af4f52..2c323d83d0526 100644
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
@@ -359,6 +360,17 @@ static void prefetch_freepointer(const struct kmem_cache *s, void *object)
 	prefetchw(object + s->offset);
 }
 
+/*
+ * When running under KMSAN, get_freepointer_safe() may return an uninitialized
+ * pointer value in the case the current thread loses the race for the next
+ * memory chunk in the freelist. In that case this_cpu_cmpxchg_double() in
+ * slab_alloc_node() will fail, so the uninitialized value won't be used, but
+ * KMSAN will still check all arguments of cmpxchg because of imperfect
+ * handling of inline assembly.
+ * To work around this problem, we apply __no_kmsan_checks to ensure that
+ * get_freepointer_safe() returns initialized memory.
+ */
+__no_kmsan_checks
 static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
 {
 	unsigned long freepointer_addr;
@@ -1709,6 +1721,7 @@ static inline void *kmalloc_large_node_hook(void *ptr, size_t size, gfp_t flags)
 	ptr = kasan_kmalloc_large(ptr, size, flags);
 	/* As ptr might get tagged, call kmemleak hook after KASAN. */
 	kmemleak_alloc(ptr, size, 1, flags);
+	kmsan_kmalloc_large(ptr, size, flags);
 	return ptr;
 }
 
@@ -1716,12 +1729,14 @@ static __always_inline void kfree_hook(void *x)
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
 
@@ -5915,6 +5930,7 @@ static char *create_unique_id(struct kmem_cache *s)
 	p += sprintf(p, "%07u", s->size);
 
 	BUG_ON(p > name + ID_STR_LENGTH - 1);
+	kmsan_unpoison_memory(name, p - name);
 	return name;
 }
 
@@ -6016,6 +6032,7 @@ static int sysfs_slab_alias(struct kmem_cache *s, const char *name)
 	al->name = name;
 	al->next = alias_list;
 	alias_list = al;
+	kmsan_unpoison_memory(al, sizeof(*al));
 	return 0;
 }
 
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-16-glider%40google.com.
