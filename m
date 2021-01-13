Return-Path: <kasan-dev+bncBDX4HWEMTEBRBNV47T7QKGQEPTDQEFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B00CF2F4FD1
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:14 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id i23sf783986lfl.10
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554934; cv=pass;
        d=google.com; s=arc-20160816;
        b=UcO9HQXmbpoNVHlKuTiQOPx0NUwYnkOHHh0wnJ8BFVFZgjMCMdz+U3uY/pLcM0Jr9U
         GcziUpWNz8XTFicgY8Dv/QMQnQfTINODm4+rD6lUgywcs/YE0xjVsJ807lZ5C+9vbf9J
         Sx64RUwlA5V2AQITGz0d76cdNt11CctsYFiGI4ZLjGOIgrnmcecz6mvKRi7LqxRwvwwS
         DoXdxx/DMSzcOFArdaLz7q3s8NJuEsYuDzNniz9+++Q9EvAstpbN124jskdc7vE0XdqE
         l2xMD1wo0B+stbt/mIkfHweIFiOCskVQ4V6roOq4Harl5Eowx4RzIRW71vu8fljc/0f3
         OBYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=dkOCjRUCYyggqdp65OkS/cTrDimVqkVRJnJXqhudpig=;
        b=oGw08IxtIrY9n2ZYEE/KXU2k/KRnX6+8AZZDGCLhccH0Lfsh5Y3gvQpi/F240tolOD
         lUG3KoPHXjoMQY24/2NsWXylvtxycCNvB+4fbvpyg9llTvLBFHhrzSS0DGwdv+OfuYIg
         9QMsjgZdTqfjudcFRP8hOw8NhC9rn0lQ9WxjX2HCsQ8LIuzFzJsZtHHmZ50oVbciE4gk
         +dUJIU+dQoXO5XP/CfHWOf86UbJz1egtQbfhx6b0KBxtEOC9HHYG/RxKMwR/yRwAk+4H
         gDXDyz4zhbhc4+zDeiRn+GiCvS48i+SEfvK95OhAt6MMpW+V14mhdBlAFG6oxe8ARymo
         nzhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OsvQLtdi;
       spf=pass (google.com: domain of 3nb7_xwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3NB7_XwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dkOCjRUCYyggqdp65OkS/cTrDimVqkVRJnJXqhudpig=;
        b=sLIq0rhiGakkVbbfLjC1wpkMwcAopEMYXKXcSiAR6FKe9xUrNpSLbPjzOnpXP+zv4T
         pYgUAVTWKfEauYOizuJAO9d5YG+c/lrm5CGa5CHnA0G/j/AAB3/azTvQDxTjLNQtY453
         8gnnWwSeOOG51J1+n0VykCxnvKq1XX8CgrBmISlSQ4BS72pP62veVrXqpKqQMxNfgsn2
         kwDEXwfKgXdoketgnSyoazKT4/YnhCQC3d8GP3T1zT31EJCCtFY3mqRnpFw9/qkLcTH7
         rze20oQ247aUj1laImSrSEijnB1quSvOFSc9LE2Tl+1kZAOGXQ8Sj6QYvOsbe9gF94pQ
         49IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dkOCjRUCYyggqdp65OkS/cTrDimVqkVRJnJXqhudpig=;
        b=r/yOKvkDnEEuFitRUMcv4ckeeATg9Wdx0bGt/vOmN4Gj42xDQMdVE2qD/3Vs/m3K6s
         T6Oro+nguBKrTvxBZcAWRUnOkJjvPo2IWK1uuIcxYC99OvkXZVYGjN6i1Q53NKodAw3z
         J79PkQQZDnCytDd7VK+wKrk/LcmLd8JkvnPA6TnNOxsTSQ+VxKSpbpw0D/zmGDWMf/KL
         95FrK+zne6sENXwClq5iPFI2hwZ859hiMkO9V48QKRE3w50ARM2sDXXJoXD3IPcj1Amf
         DjT7UEvPFdX4WVgpK2uDDgsRU7XxKhdWaMQcrNtV72OvQDImhqrE1Tze0QJNZBm0PtRw
         PxQw==
X-Gm-Message-State: AOAM531HA48vhF7m3+S/afqRx1BhnH/DGOCKZVquS2Ysg/j+7+/iFmsk
	YOU2qhJ1EITk/NAgaV7mZFc=
X-Google-Smtp-Source: ABdhPJxywA2Z/RUykSiluSW4g31Qca0eZVa8moLx0yxkyBwrrVIl0U7XiC+QnbkNmPz7cSr28kZvTg==
X-Received: by 2002:a19:38e:: with SMTP id 136mr1190225lfd.346.1610554934305;
        Wed, 13 Jan 2021 08:22:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls430921lfu.3.gmail; Wed, 13
 Jan 2021 08:22:13 -0800 (PST)
X-Received: by 2002:a05:6512:3e7:: with SMTP id n7mr1138858lfq.585.1610554933278;
        Wed, 13 Jan 2021 08:22:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554933; cv=none;
        d=google.com; s=arc-20160816;
        b=If8/r2ChHw5RydWOaGXmZRtvKGjDH4xheqaXnhPgyjs9v2/RUGMxTZhop5R+swyap9
         NrMafpLOCqDkiUWa75f/dUx4kInSIply22aj5t+zSzILD055vLWlXp4DtqamMkKbDYcF
         /9KrKfmZ+Skd0YsiZU13fRIrSnyHOqPSBXmoS0K5wK/UpLurky6ckre6aRBNo8rzuD5H
         wQxRZIUXFqOR4YKbli8Yq/QndgXG4FJZ0OulZf5Bz06J6T38Dhn6w8pu/xmcnTlHCJ0j
         FlAxJfBsDQf53bJySfjLNWxlWbmbivtDoXdCbU7UThhC1jvy3koisZU1jfT5rkFYkSXk
         djbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zPFgqVWTe4vdkLS3+pFA2cFBjG4oBenQZmF7SeNlQSE=;
        b=T1DzmQmoBoRlwK5krpVgOIHN2/x1Zgt0ObwsiYH3gWN4zQatPG1AOj3khvGIJcLxZn
         sFO5RmqFC8jc9oLhvcfQuivvr4ZMT6uKvbk8RvP+L9vNc68GhMeI2KzEuarBrnD4VZSh
         gQYm6uuBjC3+GneGAFmjyzVzrSvSBIIJnvVwaT90qvyZfjLssPYc0ewU3aaCj6tTrrrz
         PDCmIoumG49LHt2FOMSHBZFdGzaKgQOmZFi7vSpAPzNE8lBe8nZp0b5cZdEiUZJZ21p5
         wVVxngjBOEKlwwDKOdE3BTUsFG4v1ohXy4DbZVMLgRXGPYAzdApYth6AeIj5i6ntLif3
         85gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OsvQLtdi;
       spf=pass (google.com: domain of 3nb7_xwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3NB7_XwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a136si108980lfd.5.2021.01.13.08.22.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:13 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nb7_xwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id 88so1177851wrc.17
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:13 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:cc14:: with SMTP id
 h20mr45339wmb.180.1610554932643; Wed, 13 Jan 2021 08:22:12 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:38 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <77015767eb7cfe1cc112a564d31e749d68615a0f.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 11/14] kasan: fix bug detection via ksize for HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OsvQLtdi;       spf=pass
 (google.com: domain of 3nb7_xwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3NB7_XwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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

Link: https://linux-review.googlesource.com/id/Iaabf771881d0f9ce1b969f2a62938e99d3308ec5
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan-checks.h |  6 ++++++
 include/linux/kasan.h        | 16 ++++++++++++++++
 lib/test_kasan.c             | 20 ++++++++++++++++++++
 mm/kasan/common.c            | 11 ++++++++++-
 mm/kasan/generic.c           |  4 ++--
 mm/kasan/kasan.h             | 10 +++++-----
 mm/kasan/sw_tags.c           |  6 +++---
 mm/slab_common.c             | 15 +++++++++------
 8 files changed, 71 insertions(+), 17 deletions(-)

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
index 5e0655fb2a6f..b723895b157c 100644
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
 
@@ -299,6 +311,10 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 	return (void *)object;
 }
 static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
+static inline bool kasan_check_byte(const void *address, unsigned long ip)
+{
+	return true;
+}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 63252d1fd58c..710e714dc0cb 100644
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
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/77015767eb7cfe1cc112a564d31e749d68615a0f.1610554432.git.andreyknvl%40google.com.
