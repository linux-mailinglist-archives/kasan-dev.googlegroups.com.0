Return-Path: <kasan-dev+bncBCS37NMQ3YHBB774ZX5QKGQE5MTBF5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 09E9D27D5D4
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 20:35:44 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id v12sf2116373wrm.9
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 11:35:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601404543; cv=pass;
        d=google.com; s=arc-20160816;
        b=wqEc1fAdVsvce42p48SCUp0iJ9YSbCjvIpXUbZVAWfiG9dJZc8hIeGEUyo7D4f9M57
         oiUAstRvHCI/k4lTBnZHXCZKL2CTmxnX8rU0bwOz9ZyJX9fn2LifBthyTS93ms5ClYiH
         a+NPXv1neUHpjU1+1R5d6ERuno3ZILOL2ehXAxJEVeowrIsF49euBe5HD//ZXP+C+uEC
         FdrBc2L9DO9EIn8rPcBqVdOsP/iYBdRbtkuYBM1m94tvgqnMNpgcrZnHOONIt/dzMGDw
         qUPBrpYI/hH4PQUDW5ckmXpkfyjQjufzNitwV0FsGeN36b4RaQ0Xs/B9RP2v8cP10C+F
         A3hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XVp7xlTfzGAc/3ivj/infe0Whc3a6kF240vd0IKdjo8=;
        b=L18Y54z1EfmyK4AGb9Wb5DAO6xVFmfgbP+TjTJmxQsrwpEcv75y7P/nTXcBLwyDQAk
         +hjJ3PiUIj8CvLIKQ/q9FShjWQNWZcZeAlp9oYxpnsHXDv6ftRCsNACfecX6FUqV06T0
         aQu966xMLN6IWwrBp72MZ5120Y8V1w3NBcN3/jAZPBuWXZb5EMk9ZywcwOvoHiUhaEHH
         ogzkrOp19k1SbqyTtlUPu6jOcJ8gEtr5If0t0S3UfnfyZyKDkXR4aYsMVNYfar4CSqBd
         u+UTuWinq1hkx2QDyE+IVJaEdfyAspD+G+bsGNUr8V2di4+f48e2YxNt1Am1Cmje4ZMX
         hX1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XVp7xlTfzGAc/3ivj/infe0Whc3a6kF240vd0IKdjo8=;
        b=REuhYqEDFElDsA92QTd8LZICPcwjZB1Al34hTZexIfg8cSgIjLrmM6e/6O+RZrG80y
         +qHfsQIeSKkiLZMmaY5Aex2HTZCdgX1deLo0d7XfeXte9ovus3S3xi+smQJMUCk6kid3
         tvRO99LJ3R9AzobRRCX0SB6FQhTmwp6hunYW5GBQ1RWU7qVQXfa/wSPEQhbU7+i2uwz+
         xlQlZ0ocLHHSbKfXcoM0XF5lTkIfAxjzBs0Rf1TgA4eErB6khsI/u9DpM7HeZ6pIfmMJ
         nK5O+ev6Cj47Y1hO+DR4FHzNtf8rXN33f9gexzT1Nv4WMV67kck4Fg/t4mDIDL4zKbl/
         4L9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XVp7xlTfzGAc/3ivj/infe0Whc3a6kF240vd0IKdjo8=;
        b=MhEy9+pjHONhZEfIEBg/jXOO7uy4I1ReBeLpQjaEKwkIn/bwNWP+NJl7ARGIORroNS
         Gvv6YNYglP+av8yyC0Heuf6IAZ5HmSa3xJUKvFKEu3q4u0juu9wZ0xnXjc3XxHYb4rRz
         XBGLbrg7Ey5ctJEi5U9ZiRPXvdvFH/w18wet5vb9U+kjkvERQaFfVFZtgmygEMWppoOs
         eeB+HUGx8aWgOM1sApekk8DjzOBHRwzp+QvnAfMyxVJGxTlFzQeJ3Rt4WNAj6Cwqz2oN
         CwFhVTDieVE4dMPzfwxXHcTeCwU4tjCGaJ+n3Ngr2IRx+uIPQH26H/nagoLmv6P5055o
         UJBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Ln3LmDy474UcFNdpIwvNTx7/2MVzm5lcsWIzpXbQCm/yF0O/d
	iG4Ju0cGcy6PF4LauPn0bpI=
X-Google-Smtp-Source: ABdhPJx87O7RUYEMJs1UIA0ZTdDUZSTv5M4DEJar8SWhXOl85kou/7vdr+GafWIRqex6WDEV1/xBYg==
X-Received: by 2002:a1c:7714:: with SMTP id t20mr6229832wmi.55.1601404543747;
        Tue, 29 Sep 2020 11:35:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:428e:: with SMTP id k14ls2658423wrq.0.gmail; Tue, 29 Sep
 2020 11:35:42 -0700 (PDT)
X-Received: by 2002:adf:ee8d:: with SMTP id b13mr6261501wro.249.1601404542873;
        Tue, 29 Sep 2020 11:35:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601404542; cv=none;
        d=google.com; s=arc-20160816;
        b=euTpN+IUXMDKZI2wwt3YJaG48zX0R7nwjEe19Q2ZMApxVIHJjGUZTF3I6T7poKgDEJ
         0EX3k2bJidThYHhRxsuCM3gHgIM/EjfIwQgGwI+qVmPQ5FaJYhQpQE+dUrdYb4tVnljz
         Btnndj9gV2pZrrKfcgp69vApruLCwzePdcSTZgcqIqYzXq76FwIXyyKDh8y/+TeKUFn/
         unR7T/24if3sdB4+n/CMeSyhwrwGoOCnhBiT9mXSBHUrukftMSsxM0+1Fc4Wp9cSmn1q
         tvvvu45TPw9CPRIJchIQiT/hEYn7ZL1ITkV8iKd7S+/jdqAW3khsNbP69FSO17nCZAXT
         4uZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=8LfRs7pMiXG/De7Fp35AYlrA7J9JX6bB4nnk3Ktwc38=;
        b=vOkkpX74RSECKLsAVOmPVnK/m4iSLuPOa3H9qDIgVuBZZ/HRfhv7+ujV/6wPfxmxaW
         K0SSY0f4mOXbpIQanIEbulyTf6AQgcpUy12FYkgJA21Md2JXPg27K6p+Oi536yubDHbp
         hG7aspCBy3j5hU0urZ+Trr9IVJwEX0WDogRQnEMnRlmCc+WiefZZGSqr17ZneGX45iDV
         CBKKrDNgTFaoJQdI2jU5uUCe35VVQtq8cfmKjd/9KFkneTEn+t1YL3Hmjto331vBUA4O
         aew1XDvHQMX2I0WeUpkl5qV3f/Bb7Y2BfhK+9Q4hG5ZawzUrZPmZhqbFvT1Zg+mAiZTu
         RnJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f68.google.com (mail-wr1-f68.google.com. [209.85.221.68])
        by gmr-mx.google.com with ESMTPS id b1si159978wmj.1.2020.09.29.11.35.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 11:35:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.68 as permitted sender) client-ip=209.85.221.68;
Received: by mail-wr1-f68.google.com with SMTP id e16so6583075wrm.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 11:35:42 -0700 (PDT)
X-Received: by 2002:adf:dcd1:: with SMTP id x17mr6179562wrm.150.1601404542418;
        Tue, 29 Sep 2020 11:35:42 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id b188sm12151271wmb.2.2020.09.29.11.35.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 11:35:41 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
To: Kees Cook <keescook@chromium.org>,
	Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Matthew Wilcox <willy@infradead.org>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC v2 1/6] mm: Extract SLAB_QUARANTINE from KASAN
Date: Tue, 29 Sep 2020 21:35:08 +0300
Message-Id: <20200929183513.380760-2-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200929183513.380760-1-alex.popov@linux.com>
References: <20200929183513.380760-1-alex.popov@linux.com>
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.68 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

Heap spraying is an exploitation technique that aims to put controlled
bytes at a predetermined memory location on the heap. Heap spraying for
exploiting use-after-free in the Linux kernel relies on the fact that on
kmalloc(), the slab allocator returns the address of the memory that was
recently freed. Allocating a kernel object with the same size and
controlled contents allows overwriting the vulnerable freed object.

Let's extract slab freelist quarantine from KASAN functionality and
call it CONFIG_SLAB_QUARANTINE. This feature breaks widespread heap
spraying technique for exploiting use-after-free vulnerabilities
in the kernel code.

If this feature is enabled, freed allocations are stored in the quarantine
queue where they wait for actual freeing. So they can't be instantly
reallocated and overwritten by use-after-free exploits.

N.B. Heap spraying for out-of-bounds exploitation is another technique,
heap quarantine doesn't break it.

Signed-off-by: Alexander Popov <alex.popov@linux.com>
---
 include/linux/kasan.h      | 107 ++++++++++++++++++++-----------------
 include/linux/slab_def.h   |   2 +-
 include/linux/slub_def.h   |   2 +-
 init/Kconfig               |  13 +++++
 mm/Makefile                |   3 +-
 mm/kasan/Makefile          |   2 +
 mm/kasan/kasan.h           |  75 +++++++++++++-------------
 mm/kasan/quarantine.c      |   2 +
 mm/kasan/slab_quarantine.c | 106 ++++++++++++++++++++++++++++++++++++
 mm/slub.c                  |   2 +-
 10 files changed, 225 insertions(+), 89 deletions(-)
 create mode 100644 mm/kasan/slab_quarantine.c

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 087fba34b209..b837216f760c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -42,32 +42,14 @@ void kasan_unpoison_task_stack(struct task_struct *task);
 void kasan_alloc_pages(struct page *page, unsigned int order);
 void kasan_free_pages(struct page *page, unsigned int order);
 
-void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
-			slab_flags_t *flags);
-
 void kasan_poison_slab(struct page *page);
 void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
 void kasan_poison_object_data(struct kmem_cache *cache, void *object);
 void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 					const void *object);
 
-void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
-						gfp_t flags);
 void kasan_kfree_large(void *ptr, unsigned long ip);
 void kasan_poison_kfree(void *ptr, unsigned long ip);
-void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
-					size_t size, gfp_t flags);
-void * __must_check kasan_krealloc(const void *object, size_t new_size,
-					gfp_t flags);
-
-void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
-					gfp_t flags);
-bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
-
-struct kasan_cache {
-	int alloc_meta_offset;
-	int free_meta_offset;
-};
 
 /*
  * These functions provide a special case to support backing module
@@ -107,10 +89,6 @@ static inline void kasan_disable_current(void) {}
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
-static inline void kasan_cache_create(struct kmem_cache *cache,
-				      unsigned int *size,
-				      slab_flags_t *flags) {}
-
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -122,17 +100,65 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
+static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
+static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
+static inline void kasan_free_shadow(const struct vm_struct *vm) {}
+static inline void kasan_remove_zero_shadow(void *start, unsigned long size) {}
+static inline void kasan_unpoison_slab(const void *ptr) {}
+
+static inline int kasan_module_alloc(void *addr, size_t size)
+{
+	return 0;
+}
+
+static inline int kasan_add_zero_shadow(void *start, unsigned long size)
+{
+	return 0;
+}
+
+static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+{
+	return 0;
+}
+
+#endif /* CONFIG_KASAN */
+
+struct kasan_cache {
+	int alloc_meta_offset;
+	int free_meta_offset;
+};
+
+#if defined(CONFIG_KASAN) || defined(CONFIG_SLAB_QUARANTINE)
+
+void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+			slab_flags_t *flags);
+void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
+						gfp_t flags);
+void * __must_check kasan_kmalloc(struct kmem_cache *s, const void *object,
+					size_t size, gfp_t flags);
+void * __must_check kasan_krealloc(const void *object, size_t new_size,
+					gfp_t flags);
+void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
+					gfp_t flags);
+bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
+
+#else /* CONFIG_KASAN || CONFIG_SLAB_QUARANTINE */
+
+static inline void kasan_cache_create(struct kmem_cache *cache,
+				      unsigned int *size,
+				      slab_flags_t *flags) {}
+
 static inline void *kasan_kmalloc_large(void *ptr, size_t size, gfp_t flags)
 {
 	return ptr;
 }
-static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
+
 static inline void *kasan_kmalloc(struct kmem_cache *s, const void *object,
 				size_t size, gfp_t flags)
 {
 	return (void *)object;
 }
+
 static inline void *kasan_krealloc(const void *object, size_t new_size,
 				 gfp_t flags)
 {
@@ -144,43 +170,28 @@ static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 {
 	return object;
 }
+
 static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 				   unsigned long ip)
 {
 	return false;
 }
-
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
-
-static inline int kasan_add_zero_shadow(void *start, unsigned long size)
-{
-	return 0;
-}
-static inline void kasan_remove_zero_shadow(void *start,
-					unsigned long size)
-{}
-
-static inline void kasan_unpoison_slab(const void *ptr) { }
-static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
-
-#endif /* CONFIG_KASAN */
+#endif /* CONFIG_KASAN || CONFIG_SLAB_QUARANTINE */
 
 #ifdef CONFIG_KASAN_GENERIC
-
 #define KASAN_SHADOW_INIT 0
-
-void kasan_cache_shrink(struct kmem_cache *cache);
-void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
-
 #else /* CONFIG_KASAN_GENERIC */
+static inline void kasan_record_aux_stack(void *ptr) {}
+#endif /* CONFIG_KASAN_GENERIC */
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_SLAB_QUARANTINE)
+void kasan_cache_shrink(struct kmem_cache *cache);
+void kasan_cache_shutdown(struct kmem_cache *cache);
+#else /* CONFIG_KASAN_GENERIC || CONFIG_SLAB_QUARANTINE */
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
-static inline void kasan_record_aux_stack(void *ptr) {}
-
-#endif /* CONFIG_KASAN_GENERIC */
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_SLAB_QUARANTINE */
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index 9eb430c163c2..fc7548f27512 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -72,7 +72,7 @@ struct kmem_cache {
 	int obj_offset;
 #endif /* CONFIG_DEBUG_SLAB */
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) || defined(CONFIG_SLAB_QUARANTINE)
 	struct kasan_cache kasan_info;
 #endif
 
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index 1be0ed5befa1..71020cee9fd2 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -124,7 +124,7 @@ struct kmem_cache {
 	unsigned int *random_seq;
 #endif
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) || defined(CONFIG_SLAB_QUARANTINE)
 	struct kasan_cache kasan_info;
 #endif
 
diff --git a/init/Kconfig b/init/Kconfig
index d6a0b31b13dc..358c8ce818f4 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -1931,6 +1931,19 @@ config SLAB_FREELIST_HARDENED
 	  sanity-checking than others. This option is most effective with
 	  CONFIG_SLUB.
 
+config SLAB_QUARANTINE
+	bool "Enable slab freelist quarantine"
+	depends on !KASAN && (SLAB || SLUB)
+	help
+	  Enable slab freelist quarantine to delay reusing of freed slab
+	  objects. If this feature is enabled, freed objects are stored
+	  in the quarantine queue where they wait for actual freeing.
+	  So they can't be instantly reallocated and overwritten by
+	  use-after-free exploits. In other words, this feature mitigates
+	  heap spraying technique for exploiting use-after-free
+	  vulnerabilities in the kernel code.
+	  KASAN also employs this feature for use-after-free detection.
+
 config SHUFFLE_PAGE_ALLOCATOR
 	bool "Page allocator randomization"
 	default SLAB_FREELIST_RANDOM && ACPI_NUMA
diff --git a/mm/Makefile b/mm/Makefile
index d5649f1c12c0..c052bc616a88 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -52,7 +52,7 @@ obj-y			:= filemap.o mempool.o oom_kill.o fadvise.o \
 			   mm_init.o percpu.o slab_common.o \
 			   compaction.o vmacache.o \
 			   interval_tree.o list_lru.o workingset.o \
-			   debug.o gup.o $(mmu-y)
+			   debug.o gup.o kasan/ $(mmu-y)
 
 # Give 'page_alloc' its own module-parameter namespace
 page-alloc-y := page_alloc.o
@@ -80,7 +80,6 @@ obj-$(CONFIG_KSM) += ksm.o
 obj-$(CONFIG_PAGE_POISONING) += page_poison.o
 obj-$(CONFIG_SLAB) += slab.o
 obj-$(CONFIG_SLUB) += slub.o
-obj-$(CONFIG_KASAN)	+= kasan/
 obj-$(CONFIG_FAILSLAB) += failslab.o
 obj-$(CONFIG_MEMORY_HOTPLUG) += memory_hotplug.o
 obj-$(CONFIG_MEMTEST)		+= memtest.o
diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 370d970e5ab5..f6367d56a4d0 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -32,3 +32,5 @@ CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 obj-$(CONFIG_KASAN) := common.o init.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
 obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
+
+obj-$(CONFIG_SLAB_QUARANTINE) += slab_quarantine.o quarantine.o
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ac499456740f..6692177177a2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,6 +5,43 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+struct qlist_node {
+	struct qlist_node *next;
+};
+
+struct kasan_track {
+	pid_t pid;
+	depot_stack_handle_t stack;
+};
+
+struct kasan_free_meta {
+	/* This field is used while the object is in the quarantine.
+	 * Otherwise it might be used for the allocator freelist.
+	 */
+	struct qlist_node quarantine_link;
+#ifdef CONFIG_KASAN_GENERIC
+	struct kasan_track free_track;
+#endif
+};
+
+struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
+					const void *object);
+
+#if defined(CONFIG_KASAN_GENERIC) && \
+	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB)) || \
+	defined(CONFIG_SLAB_QUARANTINE)
+void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
+void quarantine_reduce(void);
+void quarantine_remove_cache(struct kmem_cache *cache);
+#else
+static inline void quarantine_put(struct kasan_free_meta *info,
+				struct kmem_cache *cache) { }
+static inline void quarantine_reduce(void) { }
+static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
+#endif
+
+#ifdef CONFIG_KASAN
+
 #define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
 #define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)
 
@@ -87,17 +124,8 @@ struct kasan_global {
 #endif
 };
 
-/**
- * Structures to keep alloc and free tracks *
- */
-
 #define KASAN_STACK_DEPTH 64
 
-struct kasan_track {
-	u32 pid;
-	depot_stack_handle_t stack;
-};
-
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 #define KASAN_NR_FREE_STACKS 5
 #else
@@ -121,23 +149,8 @@ struct kasan_alloc_meta {
 #endif
 };
 
-struct qlist_node {
-	struct qlist_node *next;
-};
-struct kasan_free_meta {
-	/* This field is used while the object is in the quarantine.
-	 * Otherwise it might be used for the allocator freelist.
-	 */
-	struct qlist_node quarantine_link;
-#ifdef CONFIG_KASAN_GENERIC
-	struct kasan_track free_track;
-#endif
-};
-
 struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 					const void *object);
-struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
-					const void *object);
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 {
@@ -178,18 +191,6 @@ void kasan_set_free_info(struct kmem_cache *cache, void *object, u8 tag);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 				void *object, u8 tag);
 
-#if defined(CONFIG_KASAN_GENERIC) && \
-	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
-void quarantine_reduce(void);
-void quarantine_remove_cache(struct kmem_cache *cache);
-#else
-static inline void quarantine_put(struct kasan_free_meta *info,
-				struct kmem_cache *cache) { }
-static inline void quarantine_reduce(void) { }
-static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
-#endif
-
 #ifdef CONFIG_KASAN_SW_TAGS
 
 void print_tags(u8 addr_tag, const void *addr);
@@ -296,4 +297,6 @@ void __hwasan_storeN_noabort(unsigned long addr, size_t size);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
 
+#endif /* CONFIG_KASAN */
+
 #endif
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 4c5375810449..61666263c53e 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -145,7 +145,9 @@ static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
 	if (IS_ENABLED(CONFIG_SLAB))
 		local_irq_save(flags);
 
+#ifdef CONFIG_KASAN
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
+#endif
 	___cache_free(cache, object, _THIS_IP_);
 
 	if (IS_ENABLED(CONFIG_SLAB))
diff --git a/mm/kasan/slab_quarantine.c b/mm/kasan/slab_quarantine.c
new file mode 100644
index 000000000000..493c994ff87b
--- /dev/null
+++ b/mm/kasan/slab_quarantine.c
@@ -0,0 +1,106 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * The layer providing KASAN slab quarantine separately without the
+ * main KASAN functionality.
+ *
+ * Author: Alexander Popov <alex.popov@linux.com>
+ *
+ * This feature breaks widespread heap spraying technique used for
+ * exploiting use-after-free vulnerabilities in the kernel code.
+ *
+ * Heap spraying is an exploitation technique that aims to put controlled
+ * bytes at a predetermined memory location on the heap. Heap spraying for
+ * exploiting use-after-free in the Linux kernel relies on the fact that on
+ * kmalloc(), the slab allocator returns the address of the memory that was
+ * recently freed. Allocating a kernel object with the same size and
+ * controlled contents allows overwriting the vulnerable freed object.
+ *
+ * If freed allocations are stored in the quarantine queue where they wait
+ * for actual freeing, they can't be instantly reallocated and overwritten
+ * by use-after-free exploits.
+ *
+ * N.B. Heap spraying for out-of-bounds exploitation is another technique,
+ * heap quarantine doesn't break it.
+ */
+
+#include <linux/kasan.h>
+#include <linux/bug.h>
+#include <linux/slab.h>
+#include <linux/mm.h>
+#include "../slab.h"
+#include "kasan.h"
+
+void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
+			slab_flags_t *flags)
+{
+	cache->kasan_info.alloc_meta_offset = 0;
+
+	if (WARN_ON(*size + sizeof(struct kasan_free_meta) > KMALLOC_MAX_SIZE)) {
+		cache->kasan_info.free_meta_offset = 0;
+		return;
+	}
+
+	if (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
+	     cache->object_size < sizeof(struct kasan_free_meta)) {
+		cache->kasan_info.free_meta_offset = *size;
+		*size += sizeof(struct kasan_free_meta);
+	}
+
+	*flags |= SLAB_KASAN;
+}
+
+struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
+				      const void *object)
+{
+	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
+	return (void *)object + cache->kasan_info.free_meta_offset;
+}
+
+bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
+{
+	quarantine_put(get_free_info(cache, object), cache);
+	return true;
+}
+
+static void *reduce_helper(const void *ptr, gfp_t flags)
+{
+	if (gfpflags_allow_blocking(flags))
+		quarantine_reduce();
+
+	return (void *)ptr;
+}
+
+void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
+						gfp_t flags)
+{
+	return reduce_helper(ptr, flags);
+}
+
+void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
+{
+	return reduce_helper(object, flags);
+}
+
+void * __must_check kasan_slab_alloc(struct kmem_cache *cache, void *object,
+					gfp_t flags)
+{
+	return reduce_helper(object, flags);
+}
+
+void * __must_check kasan_kmalloc(struct kmem_cache *cache, const void *object,
+				size_t size, gfp_t flags)
+{
+	return reduce_helper(object, flags);
+}
+EXPORT_SYMBOL(kasan_kmalloc);
+
+void kasan_cache_shrink(struct kmem_cache *cache)
+{
+	quarantine_remove_cache(cache);
+}
+
+void kasan_cache_shutdown(struct kmem_cache *cache)
+{
+	if (!__kmem_cache_empty(cache))
+		quarantine_remove_cache(cache);
+}
diff --git a/mm/slub.c b/mm/slub.c
index d4177aecedf6..6e276ed7606c 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3143,7 +3143,7 @@ static __always_inline void slab_free(struct kmem_cache *s, struct page *page,
 		do_slab_free(s, page, head, tail, cnt, addr);
 }
 
-#ifdef CONFIG_KASAN_GENERIC
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_SLAB_QUARANTINE)
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
 	do_slab_free(cache, virt_to_head_page(x), x, NULL, 1, addr);
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929183513.380760-2-alex.popov%40linux.com.
