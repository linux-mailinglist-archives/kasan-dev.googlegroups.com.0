Return-Path: <kasan-dev+bncBAABBJX6VKJQMGQE2B4CUPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 740365139A1
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 18:21:59 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id l7-20020adfa387000000b0020acc61dbaesf2122955wrb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 09:21:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651162919; cv=pass;
        d=google.com; s=arc-20160816;
        b=OofE3xGWG7BNzXu11VMB/dIrQCiXycwnpdC759MRf44nJn9J8E07Mm6CY0VP6YL0b8
         dfF6NxpXId+x2T1SBymCEHILgTlkf3/0l6EMYBpzH4yMnP8FkeTH48UrE94Rw9A3lUFk
         9Xgazd+cNcg+a66F3rfe1PPo9QnUV17mPTtVk4KlMFW/Jngm1sO8PYAVqj4bNp1hLS4S
         JCZxBoCJxIEEhlVQ9IzmSPW4WT0Jg2ILLIdg3avugE6Vhq4IhP8jcF9JMFyvMYWrk3u6
         KfZo54rp4WY2ffVyUkjX7ExfrwSk6XGNom353HqfyLVCJrdABzieW66Rgl1lz/gmg1mB
         fuRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vN4zCu6KtHEc0d4yZO6rHzoVLn4erTs/vZQ6i7+7Xjg=;
        b=pS8oz7xuwGpOInNSD40kZX5JAWFcHC2scp1jqASpuQ2eZDPw5s4fNn06oJ+LQT5TfR
         GD61vUItbC7yps5LofazSrnX0w1QcCvk2J2whtnq1jkutfHoFSWhtNY3vLdg0vAchhiU
         fP0IUeL5si85OYxfDYNUGc5oIcajEKqJWcf26XVEthUmsAjxPzyAtIXOzAvdA8wKT3fq
         X+1cgYsPMtZERUtJZybJbGRMDIjMEQ+TArMpHbVjehuRUjV94v+96yUmkSpxGHdo/B7H
         Nixj0gaXm8Ww/xargz+edypXVrnBRWNl/b2ZNoHKGCuQgkGSTD0qjR42E6OVRbHvieMm
         BaAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="scASAs6/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vN4zCu6KtHEc0d4yZO6rHzoVLn4erTs/vZQ6i7+7Xjg=;
        b=Zmm0nN3/hC+zCnLFym0YA2ahBOwWRjKu/ltVMoh2NC2FL7yjKnb3YdpQZcMyO0uFyD
         hWmOij7WO1nF/Dk+Q7FkCChQHMOvNU5YnAQyc7Wk1m97XID5RzfV017Q5Oqj/biM71xK
         UINHnc0/aUEjG1GfXtpsK7idllAQIGWdXOsQAOIGUw0FffG+4l3Lw6lpQf0ZaZLHoccQ
         2g+057cGcZ9L07e92DPdzWjWWsD3eG1XAuWhyBcigp/Tcx8mBMR9VdnTs2EVOeqNXJpY
         DJN2vjNYiG1nvtjXm41joRmYh0av6UAr8onGEmpxwL4r993JQR+cpi3Y8zTaaAUw5c2X
         HHpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vN4zCu6KtHEc0d4yZO6rHzoVLn4erTs/vZQ6i7+7Xjg=;
        b=R0Rgu+Z6tYEVsfd61m8SMUaZTzYKoIMcPCnaH8DXGHiPpKUDasLzltoetlK0LSaLRs
         EkCn/rNaSEvFtWRhwJ7WEtVksK/KopEQIAdGNqElHpkfT0ju2PoT3jxpEyGmEESAESrp
         VZK8Jicfxwtzp+M3L1cXVSTZTjB8CjtWIyMZU/DLhCfoKHdqDitfEZId6XBmBizlac+r
         wFHhd+5MZZ+lK3Juk3UitYEpcHFwqtHEFjT4xpWm7BCqWZ9MycCPYJd2fxwoEVhejYMx
         71q5Dcg1sPvvma0LDO1+DFpZYA0NmDycEJIpQUtlRJE8DyoSZOVYohUeGVfQAGN7VniH
         cC3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320mZt3ZEh9YeKL2Dk1EZQhY1UqoLKHG4czu8ZT/dBFVuSEscPw
	wG39lj7jO1EcpYpYbuFNqU8=
X-Google-Smtp-Source: ABdhPJz6lhp/l/sgxCeskGAu170iZ8pv4bL7u3AN7qg9eG8LzsyXsJAFY+tU1CG3FSpPbLIh7I0/8Q==
X-Received: by 2002:a05:6000:1688:b0:20c:45c1:237a with SMTP id y8-20020a056000168800b0020c45c1237amr38582wrd.362.1651162918970;
        Thu, 28 Apr 2022 09:21:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9a:b0:393:e698:3558 with SMTP id
 k26-20020a05600c1c9a00b00393e6983558ls244753wms.0.gmail; Thu, 28 Apr 2022
 09:21:58 -0700 (PDT)
X-Received: by 2002:a05:600c:b47:b0:394:1200:957b with SMTP id k7-20020a05600c0b4700b003941200957bmr3188546wmr.2.1651162918270;
        Thu, 28 Apr 2022 09:21:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651162918; cv=none;
        d=google.com; s=arc-20160816;
        b=FDxCCtXzBBBHRJZth7gC3yVuxNNYyXdfnDxY39LKShLC2wsdgmO+rk03Wz0NLMyuw5
         6txAFGrdAS6uHVv3TaCVFl+BnG+GjTTdXxfH+SXkUrMg5Phi39CEwyMIsu+bWgzgIyQj
         j6HKOwFqnv8o1eWS+h6vzlhxrJLlGVmcqcfE26thSKs6bfQD/KiH9srWlaflzGeYgtHO
         KUxLVjf+4C73U2P8dEz3wD5jDWqe+u+WVJxLBRZncO4an4rw89wwst7AaCBRzpnfYny2
         x2lvtDJjgxetTBeffYLRYbkp7raJF3EGkACIojViiYG/WJgugblDH9+D7PX4NVm0SbwX
         Yb0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=cbOwwdKzIP/GSDsAkRZ0QuBwdx3oi7IvMcPM3Ptuuw8=;
        b=RcsoGEVG/MR0N/VdqkxTP0xfqHqJDglOerSClDzg5gjW2jwn0aZaOlHJahcL3wyyNW
         DBUOWyH9unvuLPIviWqBN49IwtNoytkdlxBG6jRdmIh8QaKvaRpIMLhK9UmeYFfyF0Sx
         X5ntW/iFe/+bgyqbWNcj/U52FMZ1J8w+4B0n5YMcPRPaScM4E5olyKIBPDm/BrXrbhHC
         N2nJBCcm/LaAm2GSj8/mwnQGjam126c/VuYIT3xiz/JrCANhYreIYPruZk3sWKOG1pKA
         xqyuKxBqFRUkkLzs2mhijHJnxQ4432nFkwysnFGkje8Oa11SayNENaSy/kkIHovn+EYb
         Q/9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="scASAs6/";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id b12-20020a05600018ac00b00207a792d70fsi297792wri.6.2022.04.28.09.21.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Apr 2022 09:21:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/3] kasan: clean up comments in internal kasan.h
Date: Thu, 28 Apr 2022 18:21:50 +0200
Message-Id: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="scASAs6/";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Clean up comments in mm/kasan/kasan.h: clarify, unify styles, fix
punctuation, etc.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 71 +++++++++++++++++++++---------------------------
 1 file changed, 31 insertions(+), 40 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b01b4bbe0409..13681516dc08 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -42,6 +42,7 @@ static inline bool kasan_sync_fault_possible(void)
 {
 	return kasan_mode == KASAN_MODE_SYNC || kasan_mode == KASAN_MODE_ASYMM;
 }
+
 #else
 
 static inline bool kasan_stack_collection_enabled(void)
@@ -73,47 +74,41 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
 #ifdef CONFIG_KASAN_GENERIC
-#define KASAN_FREE_PAGE         0xFF  /* page was freed */
-#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
-#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
-#define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
-#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
+#define KASAN_FREE_PAGE         0xFF  /* freed page */
+#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocation */
+#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone for slab object */
+#define KASAN_KMALLOC_FREE      0xFB  /* freed slab object */
+#define KASAN_VMALLOC_INVALID   0xF8  /* inaccessible space in vmap area */
 #else
 #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
 #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
 #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
-#define KASAN_VMALLOC_INVALID   KASAN_TAG_INVALID /* only for SW_TAGS */
+#define KASAN_VMALLOC_INVALID   KASAN_TAG_INVALID /* only used for SW_TAGS */
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
+#define KASAN_KMALLOC_FREETRACK 0xFA  /* freed slab object with free track */
 #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
 
-/*
- * Stack redzone shadow values
- * (Those are compiler's ABI, don't change them)
- */
+/* Stack redzone shadow values. Compiler's ABI, do not change. */
 #define KASAN_STACK_LEFT        0xF1
 #define KASAN_STACK_MID         0xF2
 #define KASAN_STACK_RIGHT       0xF3
 #define KASAN_STACK_PARTIAL     0xF4
 
-/*
- * alloca redzone shadow values
- */
+/* alloca redzone shadow values. */
 #define KASAN_ALLOCA_LEFT	0xCA
 #define KASAN_ALLOCA_RIGHT	0xCB
 
+/* alloca redzone size. Compiler's ABI, do not change. */
 #define KASAN_ALLOCA_REDZONE_SIZE	32
 
-/*
- * Stack frame marker (compiler ABI).
- */
+/* Stack frame marker. Compiler's ABI, do not change. */
 #define KASAN_CURRENT_STACK_FRAME_MAGIC 0x41B58AB3
 
-/* Don't break randconfig/all*config builds */
+/* Dummy value to avoid breaking randconfig/all*config builds. */
 #ifndef KASAN_ABI_VERSION
 #define KASAN_ABI_VERSION 1
 #endif
@@ -141,21 +136,21 @@ struct kasan_report_info {
 	unsigned long ip;
 };
 
-/* The layout of struct dictated by compiler */
+/* Do not change the struct layout: compiler's ABI. */
 struct kasan_source_location {
 	const char *filename;
 	int line_no;
 	int column_no;
 };
 
-/* The layout of struct dictated by compiler */
+/* Do not change the struct layout: compiler's ABI. */
 struct kasan_global {
 	const void *beg;		/* Address of the beginning of the global variable. */
 	size_t size;			/* Size of the global variable. */
-	size_t size_with_redzone;	/* Size of the variable + size of the red zone. 32 bytes aligned */
+	size_t size_with_redzone;	/* Size of the variable + size of the redzone. 32 bytes aligned. */
 	const void *name;
 	const void *module_name;	/* Name of the module where the global variable is declared. */
-	unsigned long has_dynamic_init;	/* This needed for C++ */
+	unsigned long has_dynamic_init;	/* This needed for C++. */
 #if KASAN_ABI_VERSION >= 4
 	struct kasan_source_location *location;
 #endif
@@ -164,9 +159,7 @@ struct kasan_global {
 #endif
 };
 
-/**
- * Structures to keep alloc and free tracks *
- */
+/* Structures for keeping alloc and free tracks. */
 
 #define KASAN_STACK_DEPTH 64
 
@@ -183,11 +176,8 @@ struct kasan_track {
 
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
+	/* Generic mode stores free track in kasan_free_meta. */
 #ifdef CONFIG_KASAN_GENERIC
-	/*
-	 * The auxiliary stack is stored into struct kasan_alloc_meta.
-	 * The free stack is stored into struct kasan_free_meta.
-	 */
 	depot_stack_handle_t aux_stack[2];
 #else
 	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
@@ -203,18 +193,18 @@ struct qlist_node {
 };
 
 /*
- * Generic mode either stores free meta in the object itself or in the redzone
- * after the object. In the former case free meta offset is 0, in the latter
- * case it has some sane value smaller than INT_MAX. Use INT_MAX as free meta
- * offset when free meta isn't present.
+ * Free meta is stored either in the object itself or in the redzone after the
+ * object. In the former case, free meta offset is 0. In the latter case, the
+ * offset is between 0 and INT_MAX. INT_MAX marks that free meta is not present.
  */
 #define KASAN_NO_FREE_META INT_MAX
 
+/*
+ * Free meta is only used by Generic mode while the object is in quarantine.
+ * After that, slab allocator stores the freelist pointer in the object.
+ */
 struct kasan_free_meta {
 #ifdef CONFIG_KASAN_GENERIC
-	/* This field is used while the object is in the quarantine.
-	 * Otherwise it might be used for the allocator freelist.
-	 */
 	struct qlist_node quarantine_link;
 	struct kasan_track free_track;
 #endif
@@ -417,9 +407,9 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 		return;
 	/*
 	 * Explicitly initialize the memory with the precise object size to
-	 * avoid overwriting the SLAB redzone. This disables initialization in
+	 * avoid overwriting the slab redzone. This disables initialization in
 	 * the arch code and may thus lead to performance penalty. The penalty
-	 * is accepted since SLAB redzones aren't enabled in production builds.
+	 * is accepted since slab redzones aren't enabled in production builds.
 	 */
 	if (__slub_debug_enabled() &&
 	    init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
@@ -503,8 +493,9 @@ void kasan_restore_multi_shot(bool enabled);
 
 /*
  * Exported functions for interfaces called from assembly or from generated
- * code. Declarations here to avoid warning about missing declarations.
+ * code. Declared here to avoid warnings about missing declarations.
  */
+
 asmlinkage void kasan_unpoison_task_stack_below(const void *watermark);
 void __asan_register_globals(struct kasan_global *globals, size_t size);
 void __asan_unregister_globals(struct kasan_global *globals, size_t size);
@@ -573,4 +564,4 @@ void __hwasan_storeN_noabort(unsigned long addr, size_t size);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
 
-#endif
+#endif /* __MM_KASAN_KASAN_H */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl%40google.com.
