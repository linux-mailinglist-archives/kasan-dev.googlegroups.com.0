Return-Path: <kasan-dev+bncBCS37NMQ3YHBBDVU2X4QKGQE6AVWGDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id D19F7243C59
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 17:19:42 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id s23sf2208816wrb.12
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 08:19:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597331982; cv=pass;
        d=google.com; s=arc-20160816;
        b=du/af9O2XZ8YuVdkDvc6YjdRMAhxBXe86cchB2Ycqrp1AiaBfDmPJbaGa39IuaIHEE
         RE7cbkbD/t2doAIAFOn32r4x4SX3dC5U3igS7zKVN+WY4qsbJKAj49a9xzL/yRN1LQL9
         79Aalvn2v95Td3CYIBHp8NBH53JPv0UC3QyYDGu/NOV4fojx+fBK8XCdh1tGhtj6umx2
         3Clr/lDHaN03hkLUa5xga5/Ov20Cq95Uj7/UoSCJ47ce4cUc8iGSsaV1fQ8/fgMd5jcO
         vn00hatp4fg2WfEI4hIMapjH1PNV17Bmu0iyzybGWYkDRIR1mTsTutaxF4gpFRGFKuwR
         vkdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dMundCvXN3Y6vgiRYIwRQ4DfxgPjaisvgr0Ao0QYKEU=;
        b=OL4yXXr1wJSbhQgxOzIBA3JwFXiAru/hBzgHfqzePUMvQX7cvpGbgqIxoWgECbzZbv
         un8pMK65WYuJyk5KkbN8Aje1Lbf5g9ri/GjB+/qqRWvxsWWeWwOW3OHNOfh4uJUfV32F
         YiQhAGbqc6z8yh1x6b314+VlGmroXyR9o9K4ymehL8+KTL7Ed8xd9dEMd+flxYxsPSni
         08OZt96SYfEbpSAfoKf8C9y19OdXHjeeHNrwlGDhuucXZ8LUSroqkNotTaV1tPsDjlKy
         1gVZK4J/allYCDh05Tc88LvLNqch8wJsUuBg4CWneiODPWQIr/R+Y2hc25KtxzOCfzq7
         Lxyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dMundCvXN3Y6vgiRYIwRQ4DfxgPjaisvgr0Ao0QYKEU=;
        b=VES9O8HcegTvuI4dA+aHbQrFSikeTYRjB2sqTYkUyfCSlaCyPUEss804kcqrDcT2s6
         8UeMFrlf9H53zMgYUAI+serBnsCtApZj/AM+3Dhc08ELkqmPGiqm7Cx7JqzkT2b9vmYf
         mHnKLQtAgKbaJzLB1ABLy8O2JtXXow0Cq9ezOzsIrkirHfUnNHtWvm2tbMvIT5m2QIz4
         /mEMErcJ/ecFI5kBQjxe81dmu2vHj7MSUW3/uCTH4h8isZtjWz4s+8lbeIZ3DfaoitJQ
         zLEjOIHzg4Pbq+Dx23u7xw6gTFD1zIvZlSp2GOx+HGXeJZ+sjqMzBtx+IM4IFoAH2FRH
         llbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dMundCvXN3Y6vgiRYIwRQ4DfxgPjaisvgr0Ao0QYKEU=;
        b=hOBD06sriGWs9dxHFJBZGYqT1ub3qkck4+RMZRv5//UrzZEvhch9BMmo5iVHILVrww
         NvBX/06vBexuuyBzrpVMb5IDtVUxxTPb44vWASGGH9IO8mGafMz8mqczyU1ts5NQgiu0
         d9WS9Yk5KEkBhuWA7sAW02innTG6rHc/sLt5RyFLJEo7E0m9PrmfnxftzV3dGKiVyaGf
         5+aXEDgtvEsgAbpXmwq/8x2HteKFIpN/I8QfDdZs0FPgVF24RvM54GMMv84gHg3rWKkC
         xwb/8FLPXRsXyExxeFsik4HzziQnwyPsDOHWxyppGR+vnEM169xVy6Chxcah9uhPPwJP
         K5fw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532w+Q0pa8Usm0XhVWhFBDDC3gjuHtzRRz+8qBI10u4wLIVHBRQs
	H9fU7vlw0Jw+WCD4AD82DIQ=
X-Google-Smtp-Source: ABdhPJwIJ07I+5LMgS8tQlo81R8V1cAQ82wNG4FtpoGAAyi4C69BNCCRam5MNXepwtk016NIBKFKcg==
X-Received: by 2002:a5d:6748:: with SMTP id l8mr4803237wrw.358.1597331982556;
        Thu, 13 Aug 2020 08:19:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:b1cf:: with SMTP id r15ls1687113wra.3.gmail; Thu, 13 Aug
 2020 08:19:42 -0700 (PDT)
X-Received: by 2002:adf:bb83:: with SMTP id q3mr4939154wrg.58.1597331982048;
        Thu, 13 Aug 2020 08:19:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597331982; cv=none;
        d=google.com; s=arc-20160816;
        b=kAxzldZwnajKR02i4TI2JaBgMihBEPQSTtSn+Uf2Yr9ptN3K8RjGNPTPNjdcmgtEh8
         tklN1nyI+CN2pz/YsIO0KuPpMvww1ckCvjD9KkMunbw0FYyzVQDnWnXC99D+LktmPQrM
         MfEm4JI1m1EYf50vdOV4HBkroQZX9pdATsLFDBt+AcXzOQqeov/L2ZKUK55RF2bnohSn
         BXlblu7uGXaS5tzI6LYO6Pa1+f1ERA/8+8gLx+GFvsl4NS0ZLlSxefCzMFtm4Yz899+u
         7fHDipeOL6VCiOsqIi26L+Frn0EKeMbyHbnhnVfkXXsRm940bdAMGI0bbmEwNXNQ0/w9
         eexg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=P8DeDc5Ct3tTvMBOv5sqWQolQRiRapwMqRCVMUkdEF8=;
        b=ktxxVNr/pkjcKaybs6KRjAgxe62Y/coK0tyqY0HDABCDm6TGPI2XEMIaqRhROYBW4U
         xnCQaW4NMIDWjSuoNfOmTPYIiYZueJHbJVz9FE6kHF//MemAZyVmaxLnWTsbBX33AQji
         1yoUjJGNrHGdeA+mn5hY0fL77a6las1lxQjE/xfZvmQyevOB98ognV0rjpdpAka57ehI
         iq+fd3Xgvd6ocWshksyWLdQsUzD2ZeDdwhBr3fB0dWg7VvKbCAXCr3gygD+jgL4xc/5H
         wwAIAVy+vBGSr4d1IGa5nLjnhYm+Qze4rXtq4Kyrw1CSiEMz/k6kNPxYJoH/WJwNfvWv
         oP3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f68.google.com (mail-wm1-f68.google.com. [209.85.128.68])
        by gmr-mx.google.com with ESMTPS id n129si441498wma.2.2020.08.13.08.19.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Aug 2020 08:19:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as permitted sender) client-ip=209.85.128.68;
Received: by mail-wm1-f68.google.com with SMTP id t14so5384450wmi.3
        for <kasan-dev@googlegroups.com>; Thu, 13 Aug 2020 08:19:42 -0700 (PDT)
X-Received: by 2002:a05:600c:224e:: with SMTP id a14mr5024287wmm.80.1597331981430;
        Thu, 13 Aug 2020 08:19:41 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id d23sm10394044wmd.27.2020.08.13.08.19.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Aug 2020 08:19:40 -0700 (PDT)
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
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
Date: Thu, 13 Aug 2020 18:19:21 +0300
Message-Id: <20200813151922.1093791-2-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200813151922.1093791-1-alex.popov@linux.com>
References: <20200813151922.1093791-1-alex.popov@linux.com>
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.68 as
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
spraying technique used for exploiting use-after-free vulnerabilities
in the kernel code.

If this feature is enabled, freed allocations are stored in the quarantine
and can't be instantly reallocated and overwritten by the exploit
performing heap spraying.

Signed-off-by: Alexander Popov <alex.popov@linux.com>
---
 include/linux/kasan.h      | 107 ++++++++++++++++++++-----------------
 include/linux/slab_def.h   |   2 +-
 include/linux/slub_def.h   |   2 +-
 init/Kconfig               |  11 ++++
 mm/Makefile                |   3 +-
 mm/kasan/Makefile          |   2 +
 mm/kasan/kasan.h           |  75 +++++++++++++-------------
 mm/kasan/quarantine.c      |   2 +
 mm/kasan/slab_quarantine.c |  99 ++++++++++++++++++++++++++++++++++
 mm/slub.c                  |   2 +-
 10 files changed, 216 insertions(+), 89 deletions(-)
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
index d6a0b31b13dc..de5aa061762f 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -1931,6 +1931,17 @@ config SLAB_FREELIST_HARDENED
 	  sanity-checking than others. This option is most effective with
 	  CONFIG_SLUB.
 
+config SLAB_QUARANTINE
+	bool "Enable slab freelist quarantine"
+	depends on !KASAN && (SLAB || SLUB)
+	help
+	  Enable slab freelist quarantine to break heap spraying technique
+	  used for exploiting use-after-free vulnerabilities in the kernel
+	  code. If this feature is enabled, freed allocations are stored
+	  in the quarantine and can't be instantly reallocated and
+	  overwritten by the exploit performing heap spraying.
+	  This feature is a part of KASAN functionality.
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
index ac499456740f..979c5600db8c 100644
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
+	u32 pid;
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
index 000000000000..5764aa7ad253
--- /dev/null
+++ b/mm/kasan/slab_quarantine.c
@@ -0,0 +1,99 @@
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
+ * If freed allocations are stored in the quarantine, they can't be
+ * instantly reallocated and overwritten by the exploit performing
+ * heap spraying.
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
+	if (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
+	     cache->object_size < sizeof(struct kasan_free_meta)) {
+		cache->kasan_info.free_meta_offset = *size;
+		*size += sizeof(struct kasan_free_meta);
+		BUG_ON(*size > KMALLOC_MAX_SIZE);
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
index 68c02b2eecd9..8d6620effa3c 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200813151922.1093791-2-alex.popov%40linux.com.
