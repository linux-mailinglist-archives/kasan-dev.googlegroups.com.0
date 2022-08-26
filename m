Return-Path: <kasan-dev+bncBCCMH5WKTMGRBB6EUOMAMGQERX3IQ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B3A25A2A69
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:57 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id p7-20020a9d4547000000b00638eab81488sf844240oti.16
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526536; cv=pass;
        d=google.com; s=arc-20160816;
        b=yhpthu/rJIWuSaFs75keXBGfRq7/XliYOfrbujak8unak1z3NCds2mxgIXEKupoObj
         q5WdOc+T24wH0uG0yTyprxHwdE767AgToAB1XHxa/cL++3oH+olpxhCa10fSmRaG7tfY
         nOCjC9t6IASdCCi1VLYZz7TgRE+2wjXHkkzYZ6pUUX/yDxGz+oBLpaVUsJX8sACRL2H8
         EWrW4z+qbLvFUc1bGeHkv3WZJ5ngYgKF4SNqkt7Wd4PL9KIYfww3y0GUhcQCz6kpt6dn
         0gBBGd72/lnTg2Ds88ksdC+jiXlXOAKlrVfffdDTzaZ9JQ2sUwgrMlNjOijFW92+zYw/
         vTrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=7jX22c71k1LOUTS2UgUdLmyITLf+AWi6dKrO9MJb9Sw=;
        b=s+8dN2Gx7NwB9hd8TbTo1ybA/tPHW4+C0y4YvJkai8SgHvuQUVn5Hn4Zun4P3GP1kC
         DvoJlVXrjjEYteZKlext4EIoVDWK3K/tcET86sbSv7DerFVsS/MbL0HlH2+MAXSv0jVR
         1SSaMx4e+qzqy2k4IhnT+F2fOQLnMdyZziNrrmeLt+bFBIHtxUY7cgR2RQkHrQMIh6K4
         rYEZD4p5cXeefKgmpaoavlHgtmfWCGR+OtuuPHLs9Q6WCHPZRWSX9wjqf8b/f09gbxyT
         e3WXDpniMe5LEnbQY3YrTaNcB5K2EepBGnN2yxGJTcgEuphXYKeQ/3Q7EX66LP8Y859Z
         WkQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YwocNvFx;
       spf=pass (google.com: domain of 3buiiywykcq0tyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3BuIIYwYKCQ0tyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=7jX22c71k1LOUTS2UgUdLmyITLf+AWi6dKrO9MJb9Sw=;
        b=WjrdHQdmSuxDCwEyu/yz6tKDoUwU5D4VdiompPsvJJM04hgt9O+0Vqo3op+aK6sMkp
         WPhKms/JsCTSvolGstehysk/+ivmXbvmA0cKw9MyLzDtD62UxkxDZHpvl4TqvCSyrJBc
         KU6SBprjsqCmR0Q1X8np5pHFOytsla0gpMqqolReSRYJKtnlW6idYEA5THqLQ9eK/kyr
         0u/yr/8LrPG1ojFXp/VJucXpsXCAd9zuDQwuxgV1RHC2TSRlLsW0jm6b7eWRzSqXOlVw
         Sbm7QWmWTbV8uMVC0p8ekZfqY3vHyNEoGDsHcD7FAkQhcurqz2uKlx8tl6v6EFNL6Qv6
         aQQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=7jX22c71k1LOUTS2UgUdLmyITLf+AWi6dKrO9MJb9Sw=;
        b=KGfAcJqZMYfSgMZwhqZeJeRdoAMKgTAeM5r2b+SjSui7J+qx4aNswF4SnsO7LaMDWy
         cX8TPbSPFl71JIDjo78qO0/rcivKxnaoOHOzc0cSaJu451h7b7PNX+J9z0FAjWwst2Ij
         9jq2ZTJ12Svdy/xI6NXmWz7MMB0yQkRwCXW8P6gLAqmHNt0WsVsBTJTFWPwiZUiYc5Ly
         DyGmM9vFavBzT6zVNGRb9B4SJADvXWkT8Oytp02Yd1yHiy+dRvinsSTfoSzLIiCGuVQH
         yUipI0vG1tIddA7/+C4cQLoEVl6QVg+2pgMhiadmtVf7MtnR1mO2li0CjMwDulq9m6wV
         lfeg==
X-Gm-Message-State: ACgBeo3xmWVOG3lrmLTtu+Smh/XZQfSVR+9UP1r4RalGDQT0IlRtXGcZ
	VWaYRQJGCkOw6IH7fWdkNlI=
X-Google-Smtp-Source: AA6agR4pYUJ9cmQa8lMbO5s7bur9LbPnSayo7JjcxybcXVpqHfYVgBULQfaxlmtD3fST8E+XM0Tc1A==
X-Received: by 2002:a05:6870:4784:b0:10d:7a0c:2424 with SMTP id c4-20020a056870478400b0010d7a0c2424mr2038409oaq.126.1661526535815;
        Fri, 26 Aug 2022 08:08:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:256:b0:345:bc21:cf7a with SMTP id
 m22-20020a056808025600b00345bc21cf7als474844oie.1.-pod-prod-gmail; Fri, 26
 Aug 2022 08:08:55 -0700 (PDT)
X-Received: by 2002:a05:6808:10ce:b0:344:e898:3584 with SMTP id s14-20020a05680810ce00b00344e8983584mr1716633ois.36.1661526535278;
        Fri, 26 Aug 2022 08:08:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526535; cv=none;
        d=google.com; s=arc-20160816;
        b=LpuxcKU3v9onfIG2c4DGXqPzhqtExzjIuedIAnrich02uxZhzEgK3GwG6biuC10d+x
         MsF/05LK7fm1fuTsx7Yclu2FJAWwFpmBpaFd+gBQHmB3wL3u/iGqMaz0GIFmanmbTcUh
         MjbuGUIpI9lASYF0gQLoti720ujE3OcEa1079uZKIk6F4fOZcSCBaLvbkIVxfpZBTu9Y
         y2AAPMlhCp2pkzAEuM3HH9XFeyd+iT0FeMw8Fi88B9AbYxODAykfi+NeqErLYurC6CDL
         1LI+5873RK6z8x6ZvUab73R+7am82JEGnzM+rFgSpRDQ6RtIE7ZT/HFIyFJN29yjAeEj
         kIdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=jx2yh37l5SDq2Q8QSIum21pACdE/sm5g4yjUaLUM63Q=;
        b=OZKx7sm0MYF9EnFFbPAkVkRCkPIbaX+Hi9+Cp7OUGfm7mjg7IWec0nZdzM5GWiV9RV
         Yi0ZmW8gq3BDeW5ilxUEWgZuhijfQxQdA3ZT53AT1tUAPj1T0Wh+TvfIuSVnFyq/6WK2
         QMb8PNj7iVLcyh4yilWxjBhTaAAerfi3UNJjFndY+XpxLv+XZaQnlLDyQjE8J1Uj3gLZ
         XErzRENjEv4c0qfGeQ+C1mV+afOL6h7UmHUQ9L7WbLtS6+UktqQI1Gqle2hnbSWBzSEp
         XT7Jo7QyzqxotLJmGrGvjKY/3poTEX2dIr8gDVmQPmsMa7snvWOQRDJhADqzPLds3gey
         tqAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YwocNvFx;
       spf=pass (google.com: domain of 3buiiywykcq0tyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3BuIIYwYKCQ0tyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id s188-20020acadbc5000000b0034480be185csi96272oig.4.2022.08.26.08.08.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3buiiywykcq0tyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-336c3b72da5so29527217b3.6
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:55 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a81:710a:0:b0:33d:c742:4a20 with SMTP id
 m10-20020a81710a000000b0033dc7424a20mr69884ywc.343.1661526534913; Fri, 26 Aug
 2022 08:08:54 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:38 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-16-glider@google.com>
Subject: [PATCH v5 15/44] mm: kmsan: call KMSAN hooks from SLUB code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YwocNvFx;       spf=pass
 (google.com: domain of 3buiiywykcq0tyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3BuIIYwYKCQ0tyvqr4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--glider.bounces.google.com;
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
index 699fe4f5b3bee..fd76cea338878 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -15,6 +15,7 @@
 #include <linux/types.h>
 
 struct page;
+struct kmem_cache;
 
 #ifdef CONFIG_KMSAN
 
@@ -72,6 +73,44 @@ void kmsan_free_page(struct page *page, unsigned int order);
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
@@ -138,6 +177,24 @@ static inline void kmsan_copy_page_meta(struct page *dst, struct page *src)
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
index 2624b4ea3d8ef..519a7a1dcb4aa 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -26,6 +26,82 @@
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-16-glider%40google.com.
