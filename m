Return-Path: <kasan-dev+bncBDAOJ6534YNBBXUJV64AMGQE3NKW5MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F4D699B978
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 15:02:24 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-37d52ccc50esf1243468f8f.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 06:02:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728824544; cv=pass;
        d=google.com; s=arc-20240605;
        b=OQLqBdVLktRs4XVRw2iK951a1Dd/QKlK1z2qdQzEyM/UubSi0/5GNm8za8BAjdE4wp
         JiAvSZ0lBAeU1tGKE+GSVZr8DaQror6qWmBdrzmj/OxZJzekch7HMmMaiao5hkKRybt5
         CmQM3YoOB01y+kS8pbYgwcx1sO59kTvv0kDw+szmyuLCRk7gGNHdKAK4l8w2wvy0r23Q
         S/pRKIwsHo8wXCclwmb0UUB1NMjVIvGNcXf8grKfM86BGT7RKHR5J6uZzEBKTe6b1LKk
         JQgwGE3qFosXoBgJPhyrL3ebdMfVHmkygz+NjntEwoUbeuRifXirft/31p0u0jSEUfX2
         Pq9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RwPE3dnmPKpBL2CmtooquxweHgRi8dUqOw6/uILCKRM=;
        fh=Yt8v7Lad4Y3OOoGBzMNBVNcNvjMtBgOMyl0jscRSycc=;
        b=PdpR6SjM8YkTcUv35YQd5ou1xNNV7SoSm+YrpdDowxDF47u5hh5e3lVAWnN3UiSkBn
         ZdlQYD9xD2tVzHl9g/CBuRNC7CZ4jwDsvXd8Smpu8KtdoAFTM7kXVhQbw6JqHiJKJoiG
         pBIEZ3nlfZ8DCoNp5glx+LRpvSR4sKfTkyeq4io2q5jd88OO76fuu/qVLNI547LrwS37
         g+M6iUWZPYLKqN4vg6cNnBGYRJaV+RjzFPm41e1wqlBIvTP0wCXrQ1yOi5yKRVOnqpvZ
         1D8H3oHneOIEXnBeQ5gcgxmn6ivrSSUYUGK7gfP7Amm6DcjoOtW3hWCtQBHVBD3jcpaP
         8Wrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CWm2EXWE;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728824543; x=1729429343; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RwPE3dnmPKpBL2CmtooquxweHgRi8dUqOw6/uILCKRM=;
        b=UTZWoVLAt1X/7Doj25Aa5a75HBj65hRO20YBAuV1trWGMpP/IBjKDoioDwvuKmGqhj
         3gU2QWajYedPnqXRxx30NBlOS+uX/0NhDQAJGKkfNXiDCWBvpLGuVMJTF/14P+NRH7Cr
         /FtDWVrMm1b/c7LVgspEZ1INdHkFgqZMT81ixWFRLykVKZIwV3Qd0m5+6TtYJZxrys+h
         gphWTUkYK7ni8Ky4bBeYeM4TPRqPjWgY/wuxiXBcmkBv5IY4/sVUgFDoJkrl9UUKxi2M
         tl122+D7SJZgC0z/QzBt2vjSwP8zHtcEd/0++ikQhHc1H+f8Pjd/qFYupCmhWBAL3rRo
         OkJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728824543; x=1729429343; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RwPE3dnmPKpBL2CmtooquxweHgRi8dUqOw6/uILCKRM=;
        b=ZFnN4SkW2vqlV6c7KOqxl3X6zmv5LzOy7YuUCneHlLd9I1Hrx7Az4FDzTjdgGU/mij
         6CXY3DdK3tX7uZa1FuhgytRSSb8lK0jRCLQKA0zT5e1o90tIAxEJRoKzk7RSuAspbPNz
         961y1WaNAPFuC9W60nkIgwE90wbFoKmSWetW9aDIVcD9JOE9zmT7NvioUDii2JYm/A0v
         hOdlx0VYih7OBd86xaaC/KGAIllfjOHgUGiPpCNaIvW4TRS2Pf4LL7JwyPddLX7hlE6L
         osrvaqxj70YHA/ubWp+KSU3au8q4QM/ankb6Igqy64GRdj7ourD95aJdvMbJbhXOB6+M
         zrMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728824543; x=1729429343;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RwPE3dnmPKpBL2CmtooquxweHgRi8dUqOw6/uILCKRM=;
        b=Mx58tBTTBqCFQfQ99MnHtIMCOJ50W9y5cmfls3eeIJcS4ux/9eFMFKykg4ttsO2TV6
         TuQIn13UXXIKAiKB7HSyUKafjlQfd5p8AekIqkVzvbZKXaT1aChWWkB69U4H3nuynihI
         lLHnKC1LInwqX3lhP/qZPTCj1o0FfftY5q/6RmGcvlOnkZ6fdzi2syPlFrYUXPTZPO6W
         pz9v4dbkmmDyoy6RU3vtnWtSXgq1mhf8INI3lLe8yGn1BxgvwoeTmAx0yc1t5y86i4I+
         LOvrUi+VykDTmcnKvBtwne/V0vVqSI0u3frdKNGLAQbhA/RJTwL1rCjRVNitodRGLFDw
         Hdjw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpStWKVj7uteh94RdlCmqWv7lkW90M2ApofFlR+OPAVKqrgqcmiOZAxuBX/LQUBlKqkXtnpQ==@lfdr.de
X-Gm-Message-State: AOJu0YwAMfx9wfjvDwaaTN9VjoSA5HvAD6qBeT5+DjspMvkzFemviuOb
	g1gs9wcGt1bfEhINABiB24EsWi+8r4/waRolwlYvjzDTMi9UjGez
X-Google-Smtp-Source: AGHT+IEqoE2Dg1dKEw3nYlXWJBmkKOzPM3Nqh2g5Xyw0UcaUDrLK/H26ouWRFQrnYttywfmP1bo7jA==
X-Received: by 2002:a5d:4087:0:b0:374:d25f:101 with SMTP id ffacd0b85a97d-37d551e3c76mr5319881f8f.18.1728824543127;
        Sun, 13 Oct 2024 06:02:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fa50:0:b0:374:bb12:1771 with SMTP id ffacd0b85a97d-37d629fb91cls372952f8f.2.-pod-prod-07-eu;
 Sun, 13 Oct 2024 06:02:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWE0O6mlWpRdyMlK+DDGQjiFh/ozZmqiuT0EVIPqy4TdCRh5ds5U7DG+ZcRHq72Nm5ih5YKxDLJeVg=@googlegroups.com
X-Received: by 2002:adf:f008:0:b0:37d:4e74:687 with SMTP id ffacd0b85a97d-37d552edb40mr5308587f8f.41.1728824541148;
        Sun, 13 Oct 2024 06:02:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728824541; cv=none;
        d=google.com; s=arc-20240605;
        b=R3/9PA7KVr591Z1GBXW30xXDcD+kgT9JVtr/zl/ByOW3OtHcmGD1MUrdNlTbTE8l6U
         z5dM2ggOakKswZ7XhwebVpodAmApRbXV7x04t5q+yAOZ8LGRS5QjqzMZ7y6FdjJI9Qqr
         6slmIqXuaGVuMVyBIIsg3awKVgaD95sbwYej8xc8jG8qsmEzevcPb2XtGsTwqwpWDOEA
         F4nOT17b5b8choFORhEoORgR2iwCh+SZyodjUBupspFkJr5iNcPsbmE5Ib9DkezNtXPF
         Siv0xTMQA819PkPlGUK80yu3hRsJLKJK695OoB+TcXzku4crnFvgMhyw4FoWpDz+ugFW
         y6NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EOio8S+6KOqaUEgqnfvfmeW8wlYXV0IlIhkZKQFgu/c=;
        fh=lwhkqOA/BVAny+fA2lmzlnxVpfs1oi4B7e8N50o/NyA=;
        b=RrGqjcVrAlmh9bJibR1sIYgS+oL9vx7CZK20KKgCu3cm74D/dRpKBvFAl9RZfHQxHI
         8i4ZtTB22A6ErGgBlYOgqSQjD4/8/4QkI/NvmZk2LJdc1ntAaF7vXPvBkp6QOyK3scRR
         bP15eW/7HSaU332r9XZffYA1RFrzhgT/6cCLBaaY9ZtAsO4jh6XaNhiwi94JgvbIpo0T
         orOQSRhrbwRZ+EKVhJ0F6z6NK6gDnuEl17jkOiXznoZV8Ka+fYqhT8+d0o/AhXVp06Jx
         qWu5SF7qqiLvb6QR4Lvk+Mns29Jv7g74k28xTQDgmGX3Yi6Emb/2AFJHQ3qLydgzSyR+
         BfHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CWm2EXWE;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d4b7c8a21si140356f8f.5.2024.10.13.06.02.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 06:02:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id a640c23a62f3a-a99f3a5a44cso109348966b.3
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 06:02:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWItW4DOOQ7neTl5TdbMObDR96qdmSJ66ZDHEODkCXfrHrTABiAjeqid51K65narIht1RP63Eb3N1o=@googlegroups.com
X-Received: by 2002:a17:907:ea3:b0:a99:4e8c:e5c9 with SMTP id a640c23a62f3a-a99b937b7famr780021966b.20.1728824540497;
        Sun, 13 Oct 2024 06:02:20 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a9a0d9de967sm19209666b.139.2024.10.13.06.02.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 06:02:19 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: akpm@linux-foundation.org,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com,
	elver@google.com,
	corbet@lwn.net,
	alexs@kernel.org,
	siyanteng@loongson.cn,
	2023002089@link.tyut.edu.cn,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org
Subject: [PATCH v2 2/3] kasan: migrate copy_user_test to kunit
Date: Sun, 13 Oct 2024 18:02:10 +0500
Message-Id: <20241013130211.3067196-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241013130211.3067196-1-snovitoll@gmail.com>
References: <CA+fCnZdeuNxTmGaYniiRMhS-TtNhiwj_MwW53K73a5Wiui+8RQ@mail.gmail.com>
 <20241013130211.3067196-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CWm2EXWE;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::633
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Migrate the copy_user_test to the KUnit framework to verify out-of-bound
detection via KASAN reports in copy_from_user(), copy_to_user() and
their static functions.

This is the last migrated test in kasan_test_module.c, therefore delete
the file.

Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 mm/kasan/Makefile            |  2 -
 mm/kasan/kasan_test_c.c      | 39 +++++++++++++++++
 mm/kasan/kasan_test_module.c | 81 ------------------------------------
 3 files changed, 39 insertions(+), 83 deletions(-)
 delete mode 100644 mm/kasan/kasan_test_module.c

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index b88543e5c0c..1a958e7c8a4 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -46,7 +46,6 @@ endif
 
 CFLAGS_kasan_test_c.o := $(CFLAGS_KASAN_TEST)
 RUSTFLAGS_kasan_test_rust.o := $(RUSTFLAGS_KASAN)
-CFLAGS_kasan_test_module.o := $(CFLAGS_KASAN_TEST)
 
 obj-y := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
@@ -59,4 +58,3 @@ ifdef CONFIG_RUST
 endif
 
 obj-$(CONFIG_KASAN_KUNIT_TEST) += kasan_test.o
-obj-$(CONFIG_KASAN_MODULE_TEST) += kasan_test_module.o
diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9..e71a16d0dfb 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1954,6 +1954,44 @@ static void rust_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
 }
 
+static void copy_user_test_oob(struct kunit *test)
+{
+	char *kmem;
+	char __user *usermem;
+	unsigned long useraddr;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
+	int __maybe_unused unused;
+
+	kmem = kunit_kmalloc(test, size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, kmem);
+
+	useraddr = kunit_vm_mmap(test, NULL, 0, PAGE_SIZE,
+					PROT_READ | PROT_WRITE | PROT_EXEC,
+					MAP_ANONYMOUS | MAP_PRIVATE, 0);
+	KUNIT_ASSERT_NE_MSG(test, useraddr, 0,
+		"Could not create userspace mm");
+	KUNIT_ASSERT_LT_MSG(test, useraddr, (unsigned long)TASK_SIZE,
+		"Failed to allocate user memory");
+
+	OPTIMIZER_HIDE_VAR(size);
+	usermem = (char __user *)useraddr;
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		unused = copy_from_user(kmem, usermem, size + 1));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		unused = copy_to_user(usermem, kmem, size + 1));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		unused = __copy_from_user(kmem, usermem, size + 1));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		unused = __copy_to_user(usermem, kmem, size + 1));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		unused = __copy_from_user_inatomic(kmem, usermem, size + 1));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		unused = __copy_to_user_inatomic(usermem, kmem, size + 1));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		unused = strncpy_from_user(kmem, usermem, size + 1));
+}
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -2028,6 +2066,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
 	KUNIT_CASE(rust_uaf),
+	KUNIT_CASE(copy_user_test_oob),
 	{}
 };
 
diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
deleted file mode 100644
index 27ec22767e4..00000000000
--- a/mm/kasan/kasan_test_module.c
+++ /dev/null
@@ -1,81 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0-only
-/*
- *
- * Copyright (c) 2014 Samsung Electronics Co., Ltd.
- * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
- */
-
-#define pr_fmt(fmt) "kasan: test: " fmt
-
-#include <linux/mman.h>
-#include <linux/module.h>
-#include <linux/printk.h>
-#include <linux/slab.h>
-#include <linux/uaccess.h>
-
-#include "kasan.h"
-
-static noinline void __init copy_user_test(void)
-{
-	char *kmem;
-	char __user *usermem;
-	size_t size = 128 - KASAN_GRANULE_SIZE;
-	int __maybe_unused unused;
-
-	kmem = kmalloc(size, GFP_KERNEL);
-	if (!kmem)
-		return;
-
-	usermem = (char __user *)vm_mmap(NULL, 0, PAGE_SIZE,
-			    PROT_READ | PROT_WRITE | PROT_EXEC,
-			    MAP_ANONYMOUS | MAP_PRIVATE, 0);
-	if (IS_ERR(usermem)) {
-		pr_err("Failed to allocate user memory\n");
-		kfree(kmem);
-		return;
-	}
-
-	OPTIMIZER_HIDE_VAR(size);
-
-	pr_info("out-of-bounds in copy_from_user()\n");
-	unused = copy_from_user(kmem, usermem, size + 1);
-
-	pr_info("out-of-bounds in copy_to_user()\n");
-	unused = copy_to_user(usermem, kmem, size + 1);
-
-	pr_info("out-of-bounds in __copy_from_user()\n");
-	unused = __copy_from_user(kmem, usermem, size + 1);
-
-	pr_info("out-of-bounds in __copy_to_user()\n");
-	unused = __copy_to_user(usermem, kmem, size + 1);
-
-	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
-	unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
-
-	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
-	unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
-
-	pr_info("out-of-bounds in strncpy_from_user()\n");
-	unused = strncpy_from_user(kmem, usermem, size + 1);
-
-	vm_munmap((unsigned long)usermem, PAGE_SIZE);
-	kfree(kmem);
-}
-
-static int __init kasan_test_module_init(void)
-{
-	/*
-	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
-	 * report the first detected bug and panic the kernel if panic_on_warn
-	 * is enabled.
-	 */
-	bool multishot = kasan_save_enable_multi_shot();
-
-	copy_user_test();
-
-	kasan_restore_multi_shot(multishot);
-	return -EAGAIN;
-}
-
-module_init(kasan_test_module_init);
-MODULE_LICENSE("GPL");
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241013130211.3067196-3-snovitoll%40gmail.com.
