Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ6V26MAMGQEL6IK2ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DFB45AD25D
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:25:45 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id y14-20020a056402440e00b0044301c7ccd9sf5696623eda.19
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:25:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380740; cv=pass;
        d=google.com; s=arc-20160816;
        b=SvO2abTRSs/1aUbuDqW7JNvPgY2/olkpUjBWwqYHezq0fJ6PNPkWSj8Sc8IoJjbhQN
         +Y9n+N8//piLD+gHDNm43hvUBbNzY3me3CSxl2b2311QssCxK8r6iA6tlHdvRtfkMXa1
         BARMkGAjGHaknnEH3NZCdk8CQNFxomPWvsBfAQ78PD9pT5zz8rDPufqbE++WIONIWalm
         nt99Z8meIHIwZ739JZ8NgLCRpKOsm9xLwP0LGAmdK9oN/VR8JNU/SgRbsW0R/DUPK/qN
         WnLkdc/pPg4CXWkvE7vQWnESvoRXJiUkfYROkJqvSh/CkxP11HhjvYbpIkZQ+scP5jT3
         uXfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=5Uo2hN4gEvbSU+RW7tsSeBg+EekdS63+8MK8y6gPRSo=;
        b=dZrPCI+vb2IaFOFpbQG7wjxYiUBYkjw5Fo0YA82O5Gays4ugwqjIs8LOhvOvIaRG93
         aJJ9NOed37C6ofmmqoTyOQlCs3M2MhnC0f4jsoldYueesk/urSaV79L7stC999PsZG1c
         S5X5CZ6v9J/U44uQgL/C2XKR8H9wqqkChmu+VEm/W+TrBCQ8AYcJkI05JaIsh5uxSgAT
         IzMWLD0FgCHcpa82sr6f7wNqKpxfzeziF51kNEFAODVb4smCPnBG+Qha6ES9jpjEuDZJ
         CKz+93V0PvFlEbstOnfj4gEu4gO0G5Wv/x7CRXqJfVrr0ZVSSjwXp8/zClAW1Rur6f7h
         cgoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eCahA6Yl;
       spf=pass (google.com: domain of 3wuovywykcq8v0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3wuoVYwYKCQ8v0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=5Uo2hN4gEvbSU+RW7tsSeBg+EekdS63+8MK8y6gPRSo=;
        b=Zg97YTMIrS6TNSihMeG+iC5Yfs+b+s55nB5yiVBG33zUpQ4q3zq0fGEzO+nooBVsSu
         d1UHnx4W8P6XOHT5d2Gicj/5LqYvdPQjx22XV/eDY4jQaHPo4wi9RHbgdhVYJ3yWdZlH
         XiLRQYrk3As3CyDqWKQ7ueW5hdT59QgTHDzCQznhNIkEfi1/nageGzShsxv2OeAfGO8L
         OkGUmgxZi+1EVLIixYQhdkXeY+QPpP3BCPibA+Vw0dCosfksj0G2o2byzvBHeKsdqOAP
         evfwtS1ECemW2ooS/8C2lUkZfSm9O8pmiZMjv4VHTHg7Ziv5+kQD0xaUfaRKCb3D6x9o
         DeUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=5Uo2hN4gEvbSU+RW7tsSeBg+EekdS63+8MK8y6gPRSo=;
        b=Vvlv8zbx3LNfkV3G7jzX1DhMDCjWDRryUHzQWwaZGswhhl+NnDAAdz3wV3nn4DTEbp
         YO6a5jC1axS4w1KkLMZBjpD1HwdhcWKxhbn/nVlnBtC8T4D8TbAttnaE5mb/rO9fnp8Z
         9m+1Tod39iGJBX4Utwdwb2CLNpEJbfur//cBpsqcZnuST0AY9nTM9u5GujJYT8oM1DaE
         ARskjc3jaZMvkuS5Nu4MaSWLCOXq6SrzK7l++8rlIGJVqPbXruTc0Pm7fFUYafQ0LKny
         hcjFZa1nl1IdUoNDcOCKEQ1iWpzk3VVT5qu1jFLZsp5ACFsCUN6IFVcHJwJGdwJWl225
         Uzpw==
X-Gm-Message-State: ACgBeo0uFCVfVWFhsxDQc1rwufK0tkGaSj6LV0lqmCXoTjyAtgs/5ab6
	B3/4huVGUcaJklhfKwaSXhY=
X-Google-Smtp-Source: AA6agR6CmDBwkK2EGFlzfiaWp42wDf2R8Z8GQkgap88z7mUyTOoYTLg+VPr9eLkacsqIEE1dunSYLQ==
X-Received: by 2002:a05:6402:5002:b0:444:26fd:d341 with SMTP id p2-20020a056402500200b0044426fdd341mr44207551eda.351.1662380739973;
        Mon, 05 Sep 2022 05:25:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34d1:b0:447:ec6e:2ee with SMTP id
 w17-20020a05640234d100b00447ec6e02eels6880287edc.0.-pod-prod-gmail; Mon, 05
 Sep 2022 05:25:39 -0700 (PDT)
X-Received: by 2002:a05:6402:26c5:b0:448:e46f:c9f1 with SMTP id x5-20020a05640226c500b00448e46fc9f1mr23551473edd.287.1662380739046;
        Mon, 05 Sep 2022 05:25:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380739; cv=none;
        d=google.com; s=arc-20160816;
        b=nboiexAf/YUuAQCd0SsmQ9BS/ZExCpQLa4sQ6BXGHTgaN7iP/DgWkTb6tHQ8gz4ZjK
         YNzNxfgASFtrZVghb1N2CPfWRUcEPXuTBkqfLAg8VA9cp95YMKPWLRre+dsWa8O+/Cnk
         HfvZTksvxljzNecA1kpgtv8qRypQH8Te8zTE/Xv/I0b1U4fldL9bjrjgyczXtUGi6Jqu
         Q1KoAymRz+C9Kfxjdi2VtYk7afv0Rx8MpAbUk8kUyG/+lU4QgPvJc0X8sWj+UkemL7Vf
         26p6E0Xl8g0z+LaNHHDWhtoI1idmZ7LL6VvF7CWUpQzNpq/0CrJzItmogj8CE1sQvr57
         D3fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Ovg29tOGV0MBaJSgEZI8XqfnbTwhQ8WU6IE7DIFXMYM=;
        b=tgO/vged6W5Huy8TC+U27aXn/EwTuSdlJvHku83HJEmggWxSsZOT5ovcYhrf0xGCfE
         9oIQD4mm+XE56g2SQ3YkERh4ZOIsgrLGx1cunfKaj7wPOnrXw4giUty/TobkEq4pL1P1
         kcId6gbDH8KynVJuReXYkM05kfV6hp3SqyNJfZgV4xCra52b+ijFfreTBVsYYksST0SY
         YRWGt6lU7r4NYhuvDkSmlalfXEGjA0XVKMuCFlhR6kBpXB3e8GYjEyhwYdMjnLIebem8
         v2DCc04DqohQLxflMMDgabbU0GluBgraCx6fdvBQ4LAYIl/UWsqXQcnUAiPjOjF2MDh9
         LLbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eCahA6Yl;
       spf=pass (google.com: domain of 3wuovywykcq8v0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3wuoVYwYKCQ8v0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id og36-20020a1709071de400b007415240d93dsi373709ejc.2.2022.09.05.05.25.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:25:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wuovywykcq8v0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id f9-20020a056402354900b0044e0ea9eb2dso2758231edd.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:25:39 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:c002:b0:73d:d96c:c632 with SMTP id
 ss2-20020a170907c00200b0073dd96cc632mr33992978ejc.543.1662380738625; Mon, 05
 Sep 2022 05:25:38 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:23 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-16-glider@google.com>
Subject: [PATCH v6 15/44] mm: kmsan: call KMSAN hooks from SLUB code
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
 header.i=@google.com header.s=20210112 header.b=eCahA6Yl;       spf=pass
 (google.com: domain of 3wuovywykcq8v0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3wuoVYwYKCQ8v0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-16-glider%40google.com.
