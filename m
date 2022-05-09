Return-Path: <kasan-dev+bncBAABBDXR4SJQMGQETDRV7VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id D706D52019E
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 17:51:42 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id u26-20020adfb21a000000b0020ac48a9aa4sf5949063wra.5
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 08:51:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652111502; cv=pass;
        d=google.com; s=arc-20160816;
        b=tAFVyPu6NDkCDyjI0E8ah1vqx6jAC1XNQjzpQmAkEnKBo2eXczl9CImOhbik0cbgdo
         D7ROeOKZJCHqQJtfDqZTrISYXhV4W5japFxdCCM+Db3H5V9ibD/2bSdvNbldPFQ+8PUr
         JkjpOI0R8KfIDPomoIlImlMcYE/+wJBsI2Jr5MIp4zZxgp/mvyTA20PMW3nZuJVMucKy
         PlxjE1RctzfjlKHFheVP9sqsF+mTxK60QEEVrKkb1ZBnXXSGX8m7+GT3ZJ7EdXCx9c4d
         3V+NpGqNHgnyvU1BRv1/PIunqX57vEIsCYtGTjVaVEezRH5aV9MDaVYdcx/8hqyhI0Vs
         i5mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1P+G2yreZQnHrpu6G9jA9IWLeZMLpIAMleZ5eCUDlmU=;
        b=gcgkVvjB0qDbF0nRVQTD+U8FOo/dPUFIJWskyATRFeVZuX2iIq29FUeXk/tSzOHVls
         x0ZR8DMa5riKIzm5njIIxpbT/wx4FW48wpW7aqTZTI++cIS72ZyAEPdEemUp2bCo4SPB
         pyOagIaoALtKxEgcqQFmX+k+lAayK+6muRC/1JIG5AoEfQRcfjofZ963yuVIz4G1TOnA
         UBOp3F+nD3H0jNtKdz0kCHNI9eb3AtsDU7wqzSnauvoLRWL6/3WNwJt7PsZYuQEusvwX
         og08Qywd/CWhXtuiS1+y5x+y5GwMPo+yh0VimDgKmdM+idOUAu2IrFs7cpDA2bemgwuZ
         wahw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n0gexs5C;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1P+G2yreZQnHrpu6G9jA9IWLeZMLpIAMleZ5eCUDlmU=;
        b=kXCU1+dNRV4TIwqnmm8paFp22/D5Dq36xQm3zdUl03FB/tmZpmmpdw8S91+lYAF5Iu
         9SgcPdBOY8QvaUbl78LPH0vGiCRTHT9Fb8HbPMtZmPLqDqI3gxzJKEw7FCfKzbRT6BAc
         /DfVMlvcyggsVhN2JeutU0p53souhF51XS+h4qc3xgPGyzSOhnLyaNajEA63L2FCisMt
         84TTfWDFJ4aiSjbxK8tAh5vdgas0F4GdfkKKeCLVVII1eHG3YVzUiMw90KRVCyDwFxjk
         GCO4QjlFO9tMTrPs12nhqPgOW3z74PE+npguQl90xuZfk8PcezScT9Ak1Xz/7DzORA90
         S/DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1P+G2yreZQnHrpu6G9jA9IWLeZMLpIAMleZ5eCUDlmU=;
        b=4vrSrh21Lqzc9jBcQ51m4uMslC6ytk6WxN/G4n9BYEPmTXRAr3tnTMpL4GV8SV7bvb
         C4e9/DsSJL2Qt0etoYYC5OB4mA4JOd3trGkJgcadVs41RMdLYAtGMCnJvxhJ81Saz0gi
         YvxU0jHSjMvbpnAleIKi8JMiuv8wl7DPWE474IVQIjJqs2IAIAKtDf6zV/8NO/msv8MB
         JKFEzCnQGW/A5pB/azSOKu1WKXyDOPSuiC8mKhei2xcPZdy7WLvo2eTdMOmS6l0RoHO2
         KvQ7KR9BZz4ZJ2bs5znUP/d3Owi0OO30wUcDCMXBOkrBx7Wsu0yEVP4w0szkHxVut6M/
         8ZJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rvCzufKxmzhgCTpXlDluH4nJ6tfJ1xFrGtDsxAv9i4XOTnkOL
	MMShsW7LJ33KtwTqnwXFz8w=
X-Google-Smtp-Source: ABdhPJyz3geUkAXu1PC0DCGqVVUFW12NXwmkOpkvZLTpdJbER/qXIDHErDMW0TcJEFPIMqc8Wl4aFA==
X-Received: by 2002:a05:600c:1d10:b0:394:737f:e36 with SMTP id l16-20020a05600c1d1000b00394737f0e36mr16965515wms.202.1652111502475;
        Mon, 09 May 2022 08:51:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f11:b0:394:7a2e:a847 with SMTP id
 bd17-20020a05600c1f1100b003947a2ea847ls4132061wmb.0.gmail; Mon, 09 May 2022
 08:51:41 -0700 (PDT)
X-Received: by 2002:a05:600c:1293:b0:394:3940:2302 with SMTP id t19-20020a05600c129300b0039439402302mr16732763wmd.121.1652111501753;
        Mon, 09 May 2022 08:51:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652111501; cv=none;
        d=google.com; s=arc-20160816;
        b=Bdi7tYC4zsVvhJDIMSdrt1l79MbRkLHGUiifRg1nNF3ekHBkDDRqBfsK0Wnj8IL1PZ
         MZkWswZ/oj5oCrclbNeQ9aVPevkg/y52i+uetHFFGy7Gs5TPSKz33WGWbyAuJsqcvw/B
         C/AzyNbBLC0sP349Ghjl/XiVAR4vuTaCFRAN3S1ruYpNSWeUPovOwau17uj0brqLJeDE
         33NfgvEmbyasIqp4oASSJCZL07q3on/3MfL87cwgnYjKjaILS7VotrzUZR8A0jmywQzg
         JMpSTRayhkm3ZF6inWEq9l/1TS7fQuqI9kFuh/Sg79g4/3Ju7gKcj1+VxANbmccB3+IL
         edKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=eJT1KTqzq39O6p9NSa8tv7mPnliZo+mxhdkjwWmbXd4=;
        b=b3y+LHHaNVb9Cj5Tvl1T7S6zxMjmEvQAcWhpgqjJ4hNpGIFjkYZ+CZ7fUxtE8FhwpQ
         nnvFSk0KIJ6f3PtUm11kk9l+ORebn8nq1er/rqGInhDSGtxXjTQyOc8Rq9m2FzYY08f7
         0Gd0USFr26vt6bM5na36tsIziy+Wdwo2RbHE7bHpy/MH9aQMmXIOJHBCn4I0PiD5Ec+p
         4o/2oerTW6zDY0+uNDJuDKJCCINYZedOUx+1qYGZ10ZkLv9cV+3MbIjsOedyXaecpPCq
         b8VDFlS/FcX2uBgCebsD7yhDPeklBukvIdh7/COT5ID7VYgAKbwtn6x97xggNn/CV1iA
         5nRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n0gexs5C;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id p6-20020a05600c358600b003942a493261si29035wmq.1.2022.05.09.08.51.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 09 May 2022 08:51:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH v2 1/3] kasan: clean up comments in internal kasan.h
Date: Mon,  9 May 2022 17:51:34 +0200
Message-Id: <a0680ff30035b56cb7bdd5f59fd400e71712ceb5.1652111464.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=n0gexs5C;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 74 +++++++++++++++++++++---------------------------
 1 file changed, 33 insertions(+), 41 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b01b4bbe0409..fed4f7a00d33 100644
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
+/* Stack redzone shadow values. Compiler ABI, do not change. */
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
 
+/* alloca redzone size. Compiler ABI, do not change. */
 #define KASAN_ALLOCA_REDZONE_SIZE	32
 
-/*
- * Stack frame marker (compiler ABI).
- */
+/* Stack frame marker. Compiler ABI, do not change. */
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
+/* Do not change the struct layout: compiler ABI. */
 struct kasan_source_location {
 	const char *filename;
 	int line_no;
 	int column_no;
 };
 
-/* The layout of struct dictated by compiler */
+/* Do not change the struct layout: compiler ABI. */
 struct kasan_global {
 	const void *beg;		/* Address of the beginning of the global variable. */
 	size_t size;			/* Size of the global variable. */
-	size_t size_with_redzone;	/* Size of the variable + size of the red zone. 32 bytes aligned */
+	size_t size_with_redzone;	/* Size of the variable + size of the redzone. 32 bytes aligned. */
 	const void *name;
 	const void *module_name;	/* Name of the module where the global variable is declared. */
-	unsigned long has_dynamic_init;	/* This needed for C++ */
+	unsigned long has_dynamic_init;	/* This is needed for C++. */
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
@@ -417,9 +407,10 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 		return;
 	/*
 	 * Explicitly initialize the memory with the precise object size to
-	 * avoid overwriting the SLAB redzone. This disables initialization in
-	 * the arch code and may thus lead to performance penalty. The penalty
-	 * is accepted since SLAB redzones aren't enabled in production builds.
+	 * avoid overwriting the slab redzone. This disables initialization in
+	 * the arch code and may thus lead to performance penalty. This penalty
+	 * does not affect production builds, as slab redzones are not enabled
+	 * there.
 	 */
 	if (__slub_debug_enabled() &&
 	    init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
@@ -503,8 +494,9 @@ void kasan_restore_multi_shot(bool enabled);
 
 /*
  * Exported functions for interfaces called from assembly or from generated
- * code. Declarations here to avoid warning about missing declarations.
+ * code. Declared here to avoid warnings about missing declarations.
  */
+
 asmlinkage void kasan_unpoison_task_stack_below(const void *watermark);
 void __asan_register_globals(struct kasan_global *globals, size_t size);
 void __asan_unregister_globals(struct kasan_global *globals, size_t size);
@@ -573,4 +565,4 @@ void __hwasan_storeN_noabort(unsigned long addr, size_t size);
 
 void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
 
-#endif
+#endif /* __MM_KASAN_KASAN_H */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a0680ff30035b56cb7bdd5f59fd400e71712ceb5.1652111464.git.andreyknvl%40google.com.
