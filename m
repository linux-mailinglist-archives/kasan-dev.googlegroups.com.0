Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTO72L7QKGQEVX6WHSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B0602EB28D
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:30 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id f19sf397213edq.20
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871310; cv=pass;
        d=google.com; s=arc-20160816;
        b=GoYn/lD89n4NncqCbvBAMDPmtM1C2P2A02n7XgisX/H5vHLdun/4iXKTddHfWHwfO/
         p0zEGV/eW4ycSeS3C/I9V3diEH1XgAc69wf9Fh1QRPbreXOe7K1KJTtI/vgS3b8Jzivc
         Rdh/NTLMyL+Lv7gM8FY6ZycL1h8vKwa3c8+CpBTUsqnRUzMMako7HmuNQsIHPPWGGEXY
         E6elvRIy6HrMLCJKqJEd3nNQa2p1VmZCpglAADe4MmUIgJxU1M4bu6FjPPRL0HCXfS3i
         SWoEwRvQA9UoHEiWvjFD49AyxkZHhB6cgrqRsp67vw2TycOZjzP/EGSrOPHrg7vhWcWZ
         MSCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+f6WVIwZ7kaXvp5adAdQQ81gp2FKHN0t4eaxbesuIvo=;
        b=EZ/hJWRCXvGC7apX2QA2655AvsPGXb1ETmKbxAC4W1l4LjlN3Y5IT9ZkruVykJHlUX
         QzPF9zc8dhqyeEq4VaLR1x2MNdQ76nmLur+bQfDe087+wra/pB4cVB6egHrqlApmCT7m
         EBJTstq3H9el848KL0hN5ZsNP4r6xukw2e2tfA2N58nQhNNgJ4vIrZj8bgqvIqCFikSa
         2FPwJwLrxDD+n/XPCKkTcLmp5cGXvhmlKWR9DDiMlol5KSLhxP06lUZf+ogT1pXVcDsK
         XamfT2yt4x2flJGhH13FEGk7Ou0wx1WT1MfT4854EL9OVfmxpeC90DursIoEJwJncy9p
         Ax9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mXBBfUN+;
       spf=pass (google.com: domain of 3zk_0xwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zK_0XwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+f6WVIwZ7kaXvp5adAdQQ81gp2FKHN0t4eaxbesuIvo=;
        b=s/KUGXXP32I5oCLgY2IEVRC/oLpWkqi7taDOhLiT4nOiIjrq0MJ7P9ycMuWQeIYUuW
         Jlz6M9ibCM6oZt7sYa91OCtJTvuniMffhYRI+COMWsWwpTzGzAILmkpg6IeLgATgPEZR
         Of0pbBlA65otX7L43380VX19GT46q3vaSLMTMB4jhV3oln/xKChDREWbRN4xa84OBhNz
         51c4/cZoQVBbbG/TojaCEzJAONFwwn1PsachE3gwPpvNX3nEnjILIMfOPNh/yChbihbV
         +ySG9Qsx4nlBJnCsT3mkvMd6drg+ga0dCE9aM6OVFe8Vakl0mOGUJNu7vL/WUuToBd9Z
         vNSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+f6WVIwZ7kaXvp5adAdQQ81gp2FKHN0t4eaxbesuIvo=;
        b=KKJgcEyLxJV4WbAFNQGcNi3wItdmT9cSulvwx50Cw50kt+Hu0VUGAxYjs6jm+nvc9e
         y1YHKCNT55UCsp8DmHMwDGJmMCiKS7vZYqB3tu9SirkxUCZzRMYlyp/kVx1HfajepCGc
         R69Zn/He8WwYhxUY90jcuhiNY9QKWyKEjla28SdM72wB/akm+KB8RTcSjZzHBSERGOlK
         XnYjy5m0ky4R992l9SDpDmZgBHWCdRrES5IepPliY4TxNfokQMutyVeaqoYmwWbU0SNF
         4vplsA9Dva0IbqT333+mQ4RTkCXyw+yHH3pmPuYC9aLIWq65e8rnJQnASDNjHCnaD6Ks
         7xZg==
X-Gm-Message-State: AOAM5337iUcoBbdDOigMYo5dj6t8Fw9zk5Rp34SStRiSrPeBOxKOLkzB
	t4mBvqY1bsMoK/wyRhfJoWQ=
X-Google-Smtp-Source: ABdhPJzj8geIF6GfJ5Xyp3EfbmshVRpH/gRR5qJkdzNPn+YnedVLQ9P4ADeFRw6IcOF1QyIpsKKJAw==
X-Received: by 2002:a17:906:660b:: with SMTP id b11mr409486ejp.458.1609871309928;
        Tue, 05 Jan 2021 10:28:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:22d3:: with SMTP id dm19ls650661edb.2.gmail; Tue,
 05 Jan 2021 10:28:29 -0800 (PST)
X-Received: by 2002:aa7:c151:: with SMTP id r17mr1096051edp.106.1609871309105;
        Tue, 05 Jan 2021 10:28:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871309; cv=none;
        d=google.com; s=arc-20160816;
        b=n3c4ubsOdBb2lIdY80bXnk8oHw1turcceaW4Q1J3Dz8mwNNBHxDMqYJFX6gTAOJplc
         c5fRmnFB8p8vhVjMU6wHEmYi79NvRTvRYHWzVtKqmWP88x8hzb2elUGDr0sFHWWgXcpK
         p3f5+nL81aLJDKoNCZm0bFQBsr/3KY6RMeQS8fMEViV9w9jULXMuQB7b/U2z7RwZkdeE
         kvuN62J3o7jyCZm8oLMHqIEWxOYg/H/49MxZRjMhLpO7c2yCm/Zqbtzg/hexcnYmjS9J
         JyQy+PPhaoNRKlaZRdtmBq+xjP/Yo+eyk5JvUNHifjJ/9gYTrpNg03kCiaEbEtCgwvFj
         olww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=4nQbhmxnHYBZMr8XvL6GP6Xh98otRrfrKaNSbxyS0Do=;
        b=Y/WsWU04MGg1G0fhvb4ZYtMRLft9N+pxo2vhg3+GpzkieMaDqfudKPrrRq8laihqnP
         LSaeezcN2SabVEFsvSVm2thDmOlnW6E84XxH2MTlLJYCMrLOtdteQLyvwxhUgNxb5W9Q
         SvX631/LBQlSnXl4ltSOdmV4YmgWrxdA8UZUW/lUhN+p1dJD3vhTUUYUsOZIHeMwqBaX
         e9HkXPwmc3TzT238GKRJrCj68/89sXxrmetGm69wakbVNEGfc9LlBRW5cAyv6K/Udtn1
         9ZC03jIMEX5L9Q94xKk1K8bvzXdA5+pqTTiYouAOnyDxNYedhsugVir++24qk3xhXQYL
         zowQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mXBBfUN+;
       spf=pass (google.com: domain of 3zk_0xwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zK_0XwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f26si2236ejx.0.2021.01.05.10.28.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zk_0xwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id g16so196976wrv.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c044:: with SMTP id
 u4mr601060wmc.1.1609871308429; Tue, 05 Jan 2021 10:28:28 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:54 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <a83aa371e2ef96e79cbdefceebaa960a34957a79.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 10/11] kasan: fix bug detection via ksize for HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mXBBfUN+;       spf=pass
 (google.com: domain of 3zk_0xwokcqufsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3zK_0XwoKCQUfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

Also add a new ksize_uaf() test that checks that a use-after-free is
detected via ksize() itself, and via plain accesses that happen later.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Iaabf771881d0f9ce1b969f2a62938e99d3308ec5
---
 include/linux/kasan-checks.h |  6 ++++++
 include/linux/kasan.h        | 13 +++++++++++++
 lib/test_kasan.c             | 20 ++++++++++++++++++++
 mm/kasan/common.c            | 11 ++++++++++-
 mm/kasan/generic.c           |  4 ++--
 mm/kasan/kasan.h             | 10 +++++-----
 mm/kasan/sw_tags.c           |  6 +++---
 mm/slab_common.c             | 15 +++++++++------
 8 files changed, 68 insertions(+), 17 deletions(-)

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
index 5e0655fb2a6f..992ba5c653a3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -243,6 +243,18 @@ static __always_inline void kasan_kfree_large(void *ptr, unsigned long ip)
 		__kasan_kfree_large(ptr, ip);
 }
 
+/*
+ * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
+ * the hardware tag-based mode that doesn't rely on compiler instrumentation.
+ */
+bool __kasan_check_byte(const void *addr, unsigned long ip);
+static __always_inline bool kasan_check_byte(const void *addr, unsigned long ip)
+{
+	if (kasan_enabled())
+		return __kasan_check_byte(addr, ip);
+	return true;
+}
+
 bool kasan_save_enable_multi_shot(void);
 void kasan_restore_multi_shot(bool enabled);
 
@@ -299,6 +311,7 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 	return (void *)object;
 }
 static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
+static inline bool kasan_check_byte(const void *address, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 3ea52da52714..6261521e57ad 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -490,6 +490,7 @@ static void kasan_global_oob(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
+/* Check that ksize() makes the whole object accessible. */
 static void ksize_unpoisons_memory(struct kunit *test)
 {
 	char *ptr;
@@ -508,6 +509,24 @@ static void ksize_unpoisons_memory(struct kunit *test)
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
@@ -937,6 +956,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_alloca_oob_left),
 	KUNIT_CASE(kasan_alloca_oob_right),
 	KUNIT_CASE(ksize_unpoisons_memory),
+	KUNIT_CASE(ksize_uaf),
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
 	KUNIT_CASE(kasan_memchr),
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index eedc3e0fe365..45ab2c7073a8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -345,7 +345,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	if (kasan_check_invalid_free(tagged_object)) {
+	if (!kasan_check(tagged_object)) {
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
+	if (!kasan_check(address)) {
+		kasan_report_invalid_free((void *)address, ip);
+		return false;
+	}
+	return true;
+}
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index acab8862dc67..b3631ad9a8ef 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -185,11 +185,11 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
 	return check_region_inline(addr, size, write, ret_ip);
 }
 
-bool kasan_check_invalid_free(void *addr)
+bool kasan_check(const void *addr)
 {
 	s8 shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
 
-	return shadow_byte < 0 || shadow_byte >= KASAN_GRANULE_SIZE;
+	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
 }
 
 void kasan_cache_shrink(struct kmem_cache *cache)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 292dfbc37deb..f17591545279 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -329,20 +329,20 @@ static inline void kasan_unpoison(const void *address, size_t size)
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
-static inline bool kasan_check_invalid_free(void *addr)
+static inline bool kasan_check(const void *addr)
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
+bool kasan_check(const void *addr);
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index cc271fceb5d5..e326caaaaca3 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -118,13 +118,13 @@ bool kasan_check_range(unsigned long addr, size_t size, bool write,
 	return true;
 }
 
-bool kasan_check_invalid_free(void *addr)
+bool kasan_check(const void *addr)
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
index e981c80d216c..a3bb44516623 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1157,11 +1157,13 @@ size_t ksize(const void *objp)
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
+	 *
+	 * We use kasan_check_byte(), which is supported for hardware tag-based
+	 * KASAN mode, unlike kasan_check_read/write().
 	 *
 	 * If the pointed to memory is invalid we return 0, to avoid users of
 	 * ksize() writing to and potentially corrupting the memory region.
@@ -1169,7 +1171,8 @@ size_t ksize(const void *objp)
 	 * We want to perform the check before __ksize(), to avoid potentially
 	 * crashing in __ksize() due to accessing invalid metadata.
 	 */
-	if (unlikely(ZERO_OR_NULL_PTR(objp)) || !__kasan_check_read(objp, 1))
+	if (unlikely(ZERO_OR_NULL_PTR(objp)) ||
+	    !kasan_check_byte(objp, _RET_IP_))
 		return 0;
 
 	size = __ksize(objp);
-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a83aa371e2ef96e79cbdefceebaa960a34957a79.1609871239.git.andreyknvl%40google.com.
