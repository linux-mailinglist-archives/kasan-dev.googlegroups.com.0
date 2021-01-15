Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGNNQ6AAMGQEFRFPTBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6706C2F8304
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:31 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 4sf5364330ooc.21
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733210; cv=pass;
        d=google.com; s=arc-20160816;
        b=iskulJ+ZGSNF+4TVhOJt5cSKgPpBiLc8Ur+ora++6X2r0UT5r8Bvb5JLKRpUH6wwPR
         biUDPmwNi7est9nRQh3hOPDRK5vCpdJEBjnootvw6YUm8Gj7a//35tfWr4GOfMtmA+PV
         LmecN3LOETt99juOMWBOAiEtjoBdTar9hhXCSpVheucgQS8NBdy7wOJmfC8Nu8F8xsh4
         7G/ptBlwBmLgP/Gr1UNMcm3tCbM/rJW0xN8xF3NmC7X/yDuUVGp36i/CLFGKQsn6+oDE
         DI+DdybaBjUwUf56pDeCfii5KyJXyWvk2CN6QX8hCeepDff/2ctHjjEW/1c2u/6Y0L5w
         Z84Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=t2tmrqRPy99MJvVtTNkpxZh9DR4af+/wlv+PWeDUYms=;
        b=q+hEB3gqzOpwVd3asEQZ30W+QGOntjYi5/uX9LrB4fj4Ikc3H3SqUmKYtRQ6iT8WhW
         nMXQqyZKNDQ+rmIo8MXbXqAJ+j589g99zJuXuajLQlvmXO+ukl+qYPrMj8sFH8leUAFr
         4UzEPtDiBwxSXyPuelJHAOuVbaXsSKtWrPL1aH1Y32nu/E/Z179HbqxanKr3/LVDiAan
         MH6y2SvXZpLv6Nxghv5SwPsszGbweOWtCsTj8iUZGqJnIffltKElhvEuYYTNvVGZjok7
         xwM7FxUbMXtVnoNLENBhHqPparUJbsPB7DKng68GJ229b49uM3dq5N1I8yl2opecMnE6
         tq5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YP8oChHh;
       spf=pass (google.com: domain of 3mdybyaokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3mdYBYAoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=t2tmrqRPy99MJvVtTNkpxZh9DR4af+/wlv+PWeDUYms=;
        b=bBPSKeNxkxawNj/xvwp9xTEm2rWV8aQtTXnBbaMHxUdVWU9fDY9DM771jIJUeZw1//
         foI9Q4/ovHt0Yd9rQFUsc3QrJurRH4AHmGoWcZF3hkIYoviFdUmP2v9Pz4Oc9Z9MC7zy
         J4zif24BMRwjP0Jb6bS4H39KoE71lb8J860sYu6zcBn2Bkf7kBCf57fIfgh5C9/JOegu
         sYiYlLb88jQogM5Ua7UX43SReJ5YDwfOFGOU7w5StT316EkHgpG9f6ttxnpLPAV3/BEG
         tE1air7kGErSwI3sKeKIx+7L0aBGN1bo/+khMGFo/QJHlu/mcU95FSBpq/Pi/gFU+1PJ
         KSpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t2tmrqRPy99MJvVtTNkpxZh9DR4af+/wlv+PWeDUYms=;
        b=TnW5hv0JPTs5bJLgcOmGBoR+Re3+Wh56hzfq9Ro7NUYWlKhn8mFZwRD0VwK6YQDugG
         VR9xUhEWWxGACk1CqEyxKmorfCfYeN7xk+o/QEVV2M4RPlh+eyKFsb1AlswlTE02KOjW
         c7Ws7c6uO9BxlUVzlWa21tpM33PDySjQ3rfGEl/65WDUo0buIK+6RHUNSC7DwPNv74M0
         Kc03zrbLSDsooNYexy0igLJzjorOg+zOsLrzejsuC1eQUlBK8UqTbU6gTwPdrKJcDre0
         W3H5+xhZWbxZg6y8yqTpMtRMqvY/XgQN2v0MAi/uNpIATJq3BVBnyDVBqr7I62fwkoKg
         ADtg==
X-Gm-Message-State: AOAM531W6sIDzIfAmu6htwRaYHFco+jjEWSsQNRgFCCmKs9+2FPty9rM
	kMh26dKkbIsaHqK4es31xAA=
X-Google-Smtp-Source: ABdhPJwDTT2DREyWZylTqU8kzvjfzS8xFppHT6437j2m/hUcIjtndL/EA1nq1dPdBcFp7rGwHYYvHA==
X-Received: by 2002:a4a:946d:: with SMTP id j42mr9091127ooi.39.1610733209977;
        Fri, 15 Jan 2021 09:53:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c413:: with SMTP id u19ls2350933oif.11.gmail; Fri, 15
 Jan 2021 09:53:29 -0800 (PST)
X-Received: by 2002:aca:33d5:: with SMTP id z204mr6278159oiz.81.1610733209611;
        Fri, 15 Jan 2021 09:53:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733209; cv=none;
        d=google.com; s=arc-20160816;
        b=t32RxWljHuxrnpt/iAOic0ibS8Oq330JURieIDy73uF4NF1bFFDulIxlfDikj7ObXs
         +Vkv4bcb6szjhA7rh15CCmenagE7p6jPysisDjj+skcWZDa7MHfoQFSM+7Se/PvQbJ7z
         zMnaXP3C+yZXxN7bTF7rqZyXeWe2T44QXzWyi3DmL78e61JTZgYgIC2V/n1b9hxbw5sm
         3oKjd5vfwXQlqpcpUJgSNh3QuzGI0s9cpzcblwHBGaKuu6jTyzjjFI+hDsXBPn6ZaiEM
         D+bg5uCTBpfL8uoHszUfngxfzwF122PGuYKeMIYz1+kBsGoZzfPb9FbrBu+ozlUx8S+0
         ID0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=i4Pa52MGBLEd7FgtQKA721g3k7bJs7J0gJd7r1iU8wY=;
        b=AytDGgeDlyNyVFChiXCZl34sjT1CoDhOfbgIP1gCFGTbEAJGRCXIXJ/dZQNyNhYw83
         eTEY5xvBlvol0LqcD9m8Khkns2N9d6h5X6rPFD9oFVsjUpyHPZE7LnnsdAZyRc01sDB/
         GacBTXsBJHkS6GLU8tLAVS2EXFwnYDnmrsCdBxXRCJVsZNmoMv+Kv/pPiaGNvzfzcyY9
         P4G7dATpUv0XXvD5WpvHU+OOpavZs9LoUCukeA7dRtSETCj8Ma69z+u25iF7tEMA8ZxG
         1acPJMU2hmQ4Qy69hWunrJhNXkyBYeeCPskI3Qaq4oNLx3kZIi1ijCSpj2Tih+jePaeB
         yYKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YP8oChHh;
       spf=pass (google.com: domain of 3mdybyaokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3mdYBYAoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id v23si973836otn.0.2021.01.15.09.53.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mdybyaokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i13so7995588qtp.10
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e5a:: with SMTP id
 z26mr13500299qve.2.1610733209000; Fri, 15 Jan 2021 09:53:29 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:49 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <f32ad74a60b28d8402482a38476f02bb7600f620.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 12/15] kasan: fix bug detection via ksize for HW_TAGS mode
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
 header.i=@google.com header.s=20161025 header.b=YP8oChHh;       spf=pass
 (google.com: domain of 3mdybyaokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3mdYBYAoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f32ad74a60b28d8402482a38476f02bb7600f620.1610733117.git.andreyknvl%40google.com.
