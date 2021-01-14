Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX52QKAAMGQEH3DO4LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3874E2F6B22
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:37:04 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id r185sf2925821ybf.9
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:37:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653023; cv=pass;
        d=google.com; s=arc-20160816;
        b=qk0xASAdWzhR029NpK4HZSfanLETTDN+f/jwwPsD5nEAW7/C/qcjOGu+Yq5Tej/aUs
         bJxb1bZaXJliMNEDamFcB8ZicPPpyMR6od2N5b1Vchd0CDeZ9ZZd/tQy4HKoYAxM0SvQ
         FdMiC/Z7fdCcMhiIZb1oA4DDZkrWk91QqQJ8QXmluq7yWozw9qThsr7UTbO300CjQxav
         zaoiBCItvms05WwkET4aVEvm8586w2bJwZpMMsoMfnNNLeGzBphUI/wJ5I7XbCqftSjg
         Fsv/g/FJ+l/sLZ8I1GrVHFY3MjTcecqT0d/sApP3wvS4Phuk6GigQnk96lecOJARAzMZ
         yAUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=NUgr8SyR376QYURgXrsapvylYLwJDZU7Btwl5xarqsA=;
        b=0fmhmkXHSwlNKSpqJhvSSslbhPDPDRclrVU3f7/APY8ynls9/9iDXauv4F3jFClpbE
         uVPoI8jNgt+R27Q1eB7404ZzNFjNhE0TuQLFyOt7cyLHjDuQHwLphqCzCPoSZZT0I+GD
         c1/oh3zvEo97+FZoy52SraYvZsb82Niz0UI4boTbLz33DHMEQzY2vHzTYq+VAh1zClDF
         KZj+DfgcmkrxTbcReOp+M0vH5zHznlsL8yro5IywlY0tRJmMFIIhjlAZy4S83sQxx5k/
         jI7qiP9cvjM15NdL16ckAiEh6CbL8jt1TOdUVIV1yJv9bAEx4+VvPNownGBWJJheAt4g
         IiCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K3nDF+rO;
       spf=pass (google.com: domain of 3xp0ayaokcaeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Xp0AYAoKCaEBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NUgr8SyR376QYURgXrsapvylYLwJDZU7Btwl5xarqsA=;
        b=LUbR2N1a7DVxL2CENIy6xghuEE/9qnVV77RyEKw/iZ8DQ8AiLM5eu7JspuuV7DHppc
         69L54OF4T52nYm/1YORmjnOi85PaPWYA2QJLea9+1hFV/4CxMdDaCgdnRdQp5nx9dx2j
         5p/nZyw+EkBPUqNFpOQsLNVk3WyGqzaNXNvb3AznzgE2wsEJFP+eghOsUIQzR/GNvQky
         S4FrpEIDgOEfDQcaIAyE0JetBFMfUevP7MlXQkW58Df1/ZgM+46uHd27GYei5CxcgnG3
         beLB7O7l/wE7jhOfToMLU3i1NoPlw6M4RLBAy4902vplonmyr6Vjx9lhvNerEwWVYXU4
         D4gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NUgr8SyR376QYURgXrsapvylYLwJDZU7Btwl5xarqsA=;
        b=W5yN/N2S6yISTl12e53aOVcwQKCnBDs0/Vhk0dCiyi2J7FTUuPZid1RpnsFJ1FNrPm
         pihVGH0Hde0FfvJwsLI9gpz8MYagN1KDO+Ni0G6lfysiEel3BOz+OcdYED+p7xYX/ZxA
         8TGLICg13SaG1gCcnpnlEx0jWfD6VCUkw6VWuSrHtqXrafvENUmCYThOToYxRyPkCkIJ
         jggH/s3j5zmCCWsOFbDksxRi1yM5DzOe4kB/xuL+sqD5Tu3oXA4o5sfwIu+o5Ua4By/n
         fEK2sROJrsMGt5nMINpnwFNU2UcyELhnAq/t8SmbLQC94cC1HiNpiO2KNVNwQ9yuFCh8
         ueAA==
X-Gm-Message-State: AOAM5320jDxAj0+SzThjmhsmCHc3QhaJxSr+eil0ZKZBC6sdtsr/W9S2
	BVmOhX51qsL90NlR/xga4B4=
X-Google-Smtp-Source: ABdhPJxJmkgjVm0V36hSZ4/Ke+DIUpW4kn/XgHCAWP9/9+B5VX651TAcFq2/BLAc3Qr7STHYJe3i1Q==
X-Received: by 2002:a25:1541:: with SMTP id 62mr13135544ybv.484.1610653023228;
        Thu, 14 Jan 2021 11:37:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e407:: with SMTP id b7ls3218003ybh.6.gmail; Thu, 14 Jan
 2021 11:37:02 -0800 (PST)
X-Received: by 2002:a25:1654:: with SMTP id 81mr12439280ybw.508.1610653022804;
        Thu, 14 Jan 2021 11:37:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653022; cv=none;
        d=google.com; s=arc-20160816;
        b=KweyPF2fzqxbPVjxi0k30DftRXxp9VI9ms2YNASIL0NZ1zqqC1YH1ag7ZWoriGZtQl
         7839V73/QhbClhGj+/MEqPD3LH9Dwac61+7N9KgpxvG3Zpbpriidr0poWx6Y/XDweed6
         JKxM7mJFInG9Z7UHHD+JwKYTAhewOLh4Fon5pzQioF2a5D9GYjunYrbP5hLs1LG3D+nW
         G1jcM7gAfFl4zwB+iHk/H3K8c7oaCoQeweqtFXQyLRK5RNKxXEdW3KpvXZULfUbRy/4n
         +k7sXTmTtd3wlbNUOIGsqHuwhKNlrD5Gfax5GndWNCJF9Tv8S7UOAPSFrqoBEHhxMImY
         rEDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=5ICiHU9eH9X2+10P7u0qvxxJHOFuWSeCOFkODXCmirc=;
        b=NAPiWiFk7yqxVAmJsMDotD2UlmFz2cFF6BN99la5a4s6yEiITtygAf3egAqiCubRZb
         ayJmfcP+YzdXNQNMTQhCUjEh9IpdEUGe/aoL40H1A2wyivfZKkC7NV3la2qOPc8fkwq7
         u/Agb7/cv/ehoCCZ9QiJ4J91RTbf8oiSnueRzBrhI/QevYFzaBVdfohjUDYKUDXlZ55m
         GVxSRdfJaWQ3nyQ9oJ9yN9//LjbbGdjpkW1s/1Vjg5f94eo/n+wlxCBZ692bjBRX3n/r
         i7wkxAXmv60YgcQQ1vf319iH7LJYKZq+A2sXbC0gn41xK/wUg6cwhAbR+lX7KEBS8pee
         cflg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K3nDF+rO;
       spf=pass (google.com: domain of 3xp0ayaokcaeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Xp0AYAoKCaEBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id s187si501216ybc.2.2021.01.14.11.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:37:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xp0ayaokcaeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id b8so5311782qtr.18
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:37:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4952:: with SMTP id
 o18mr8378490qvy.27.1610653022408; Thu, 14 Jan 2021 11:37:02 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:28 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <bb93ea5b526a57ca328c69173433309837d05b25.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 12/15] kasan: fix bug detection via ksize for HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K3nDF+rO;       spf=pass
 (google.com: domain of 3xp0ayaokcaeboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Xp0AYAoKCaEBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

The currently existing kasan_check_read/write() annotations are intended
to be used for kernel modules that have KASAN compiler instrumentation
disabled. Thus, they are only relevant for the software KASAN modes that
rely on compiler instrumentation.

However there's another use case for these annotations: ksize() checks
that the object passed to it is indeed accessible before unpoisoning the
whole object. This is currently done via __kasan_check_read(), which is
compiled away for the hardware tag-based mode that doesn't rely on
compiler instrumentation. This leads to KASAN missing detecting some
memory corruptions.

Provide another annotation called kasan_check_byte() that is available
for all KASAN modes. As the implementation rename and reuse
kasan_check_invalid_free(). Use this new annotation in ksize().
To avoid having ksize() as the top frame in the reported stack trace
pass _RET_IP_ to __kasan_check_byte().

Also add a new ksize_uaf() test that checks that a use-after-free is
detected via ksize() itself, and via plain accesses that happen later.

Link: https://linux-review.googlesource.com/id/Iaabf771881d0f9ce1b969f2a62938e99d3308ec5
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan-checks.h |  6 ++++++
 include/linux/kasan.h        | 17 +++++++++++++++++
 lib/test_kasan.c             | 20 ++++++++++++++++++++
 mm/kasan/common.c            | 11 ++++++++++-
 mm/kasan/generic.c           |  4 ++--
 mm/kasan/kasan.h             | 10 +++++-----
 mm/kasan/sw_tags.c           |  6 +++---
 mm/slab_common.c             | 16 +++++++++-------
 8 files changed, 72 insertions(+), 18 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index ca5e89fb10d3..3d6d22a25bdc 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -4,6 +4,12 @@
 
 #include <linux/types.h>
 
+/*
+ * The annotations present in this file are only relevant for the software
+ * KASAN modes that rely on compiler instrumentation, and will be optimized
+ * away for the hardware tag-based KASAN mode. Use kasan_check_byte() instead.
+ */
+
 /*
  * __kasan_check_*: Always available when KASAN is enabled. This may be used
  * even in compilation units that selectively disable KASAN, but must use KASAN
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bba1637827c3..5bedd5ee481f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -242,6 +242,19 @@ static __always_inline void kasan_kfree_large(void *ptr)
 		__kasan_kfree_large(ptr, _RET_IP_);
 }
 
+/*
+ * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
+ * the hardware tag-based mode that doesn't rely on compiler instrumentation.
+ */
+bool __kasan_check_byte(const void *addr, unsigned long ip);
+static __always_inline bool kasan_check_byte(const void *addr)
+{
+	if (kasan_enabled())
+		return __kasan_check_byte(addr, _RET_IP_);
+	return true;
+}
+
+
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
 
@@ -297,6 +310,10 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 	return (void *)object;
 }
 static inline void kasan_kfree_large(void *ptr) {}
+static inline bool kasan_check_byte(const void *address)
+{
+	return true;
+}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index a06e7946f581..566d894ba20b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -496,6 +496,7 @@ static void kasan_global_oob(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
+/* Check that ksize() makes the whole object accessible. */
 static void ksize_unpoisons_memory(struct kunit *test)
 {
 	char *ptr;
@@ -514,6 +515,24 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	kfree(ptr);
 }
 
+/*
+ * Check that a use-after-free is detected by ksize() and via normal accesses
+ * after it.
+ */
+static void ksize_uaf(struct kunit *test)
+{
+	char *ptr;
+	int size = 128 - KASAN_GRANULE_SIZE;
+
+	ptr = kmalloc(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	kfree(ptr);
+
+	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *(ptr + size));
+}
+
 static void kasan_stack_oob(struct kunit *test)
 {
 	char stack_array[10];
@@ -907,6 +926,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_alloca_oob_left),
 	KUNIT_CASE(kasan_alloca_oob_right),
 	KUNIT_CASE(ksize_unpoisons_memory),
+	KUNIT_CASE(ksize_uaf),
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
 	KUNIT_CASE(kasan_memchr),
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index eedc3e0fe365..b18189ef3a92 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -345,7 +345,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	if (kasan_check_invalid_free(tagged_object)) {
+	if (!kasan_byte_accessible(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
@@ -490,3 +490,12 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 		kasan_report_invalid_free(ptr, ip);
 	/* The object will be poisoned by kasan_free_pages(). */
 }
+
+bool __kasan_check_byte(const void *address, unsigned long ip)
+{
+	if (!kasan_byte_accessible(address)) {
+		kasan_report((unsigned long)address, 1, false, ip);
+		return false;
+	}
+	return true;
+}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index acab8862dc67..3f17a1218055 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -185,11 +185,11 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
 	return check_region_inline(addr, size, write, ret_ip);
 }
 
-bool kasan_check_invalid_free(void *addr)
+bool kasan_byte_accessible(const void *addr)
 {
 	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
 
-	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
+	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
 }
 
 void kasan_cache_shrink(struct kmem_cache *cache)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 292dfbc37deb..bd4ee6fab648 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -329,20 +329,20 @@ static inline void kasan_unpoison(const void *address, size_t size)
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
-static inline bool kasan_check_invalid_free(void *addr)
+static inline bool kasan_byte_accessible(const void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
-	u8 mem_tag = hw_get_mem_tag(addr);
+	u8 mem_tag = hw_get_mem_tag((void *)addr);
 
-	return (mem_tag == KASAN_TAG_INVALID) ||
-		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
+	return (mem_tag != KASAN_TAG_INVALID) &&
+		(ptr_tag == KASAN_TAG_KERNEL || ptr_tag == mem_tag);
 }
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
 void kasan_poison(const void *address, size_t size, u8 value);
 void kasan_unpoison(const void *address, size_t size);
-bool kasan_check_invalid_free(void *addr);
+bool kasan_byte_accessible(const void *addr);
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index cc271fceb5d5..94c2d33be333 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -118,13 +118,13 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
 	return true;
 }
 
-bool kasan_check_invalid_free(void *addr)
+bool kasan_byte_accessible(const void *addr)
 {
 	u8 tag = get_tag(addr);
 	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(kasan_reset_tag(addr)));
 
-	return (shadow_byte == KASAN_TAG_INVALID) ||
-		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
+	return (shadow_byte != KASAN_TAG_INVALID) &&
+		(tag == KASAN_TAG_KERNEL || tag == shadow_byte);
 }
 
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
diff --git a/mm/slab_common.c b/mm/slab_common.c
index e981c80d216c..9c12cf4212ea 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1157,19 +1157,21 @@ size_t ksize(const void *objp)
 	size_t size;
 
 	/*
-	 * We need to check that the pointed to object is valid, and only then
-	 * unpoison the shadow memory below. We use __kasan_check_read(), to
-	 * generate a more useful report at the time ksize() is called (rather
-	 * than later where behaviour is undefined due to potential
-	 * use-after-free or double-free).
+	 * We need to first check that the pointer to the object is valid, and
+	 * only then unpoison the memory. The report printed from ksize() is
+	 * more useful, then when it's printed later when the behaviour could
+	 * be undefined due to a potential use-after-free or double-free.
 	 *
-	 * If the pointed to memory is invalid we return 0, to avoid users of
+	 * We use kasan_check_byte(), which is supported for the hardware
+	 * tag-based KASAN mode, unlike kasan_check_read/write().
+	 *
+	 * If the pointed to memory is invalid, we return 0 to avoid users of
 	 * ksize() writing to and potentially corrupting the memory region.
 	 *
 	 * We want to perform the check before __ksize(), to avoid potentially
 	 * crashing in __ksize() due to accessing invalid metadata.
 	 */
-	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !__kasan_check_read(objp, 1))
+	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !kasan_check_byte(objp))
 		return 0;
 
 	size = __ksize(objp);
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bb93ea5b526a57ca328c69173433309837d05b25.1610652890.git.andreyknvl%40google.com.
