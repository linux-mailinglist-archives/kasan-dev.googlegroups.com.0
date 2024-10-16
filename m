Return-Path: <kasan-dev+bncBDAOJ6534YNBBHH2X24AMGQENGQR35Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 19A289A0B34
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 15:18:22 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-539fdef0040sf2178250e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 06:18:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729084701; cv=pass;
        d=google.com; s=arc-20240605;
        b=ijE7/+zhguPRTOm+w2CKN2OSZMlhpMqqRAKjmygZpsutI/XdgcZqLC9WIf+8S7pG4g
         MpBI3dIMiu8RKdDDF0D2qckXwOgtAfe6KMQX89VVSA+Bht+eXp1f7zH//UI/a4SJys2l
         ZVCFUqO2nwl//7n7qq2TQ3C7UYyqOznO+Z03/hlgbGlL7rCMow1/C2Bc5+arGAkXuGbI
         MWSSxRLMVEGD+ToILD4icDVsnLZyGNfSYMI7abB9Lpk4Pvm0/0A3UxWcgnPCyw+LGW/Z
         OSLEFoRPrx5yfNxPowYP3fzdPeCpyGyWrxQvf3IdGglbuNfUtH8xurLzWzFMhWu+aTGv
         1HVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Hn9yBFZWKU9rCR8LGmpBsb5Z29tVN2THo/euMT6UNA0=;
        fh=27HeUER7b6WRN5vYUOOqOdPLVg2qV6Uc4X/ZsLpieP8=;
        b=h8gvWxd9ggoPxLa5TDOhn9h0R/Z7BjIHS280U77ERm93+/lG4Tfmr+c+9jtytwVqo9
         KutzdhYdf5qKLh6OeGc+3WcENDr9cVJJKWELZsp/W3FjLsq33ZXPUklFaMOJ1KYAKghj
         rYhVgLz6T8++O/TChD3gj6off5rNkGZqGJ9XQ8KvGkegJ1mOhLkUtdsqsQ4VkzufUnkh
         +xfrjt19N391G5fEB9+j2JSKufK+X2CrbjjTpGgUHQawyZbKDERL/frDg5cINIQf9C7T
         y0KHTYQF0wTEUzc6EQ8ZB+10kltbDZ/i5xTHZ92SGgAGGDtl21vcsD1awtOIhUhwrsyz
         wOHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=b9jMqyRM;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729084701; x=1729689501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hn9yBFZWKU9rCR8LGmpBsb5Z29tVN2THo/euMT6UNA0=;
        b=WfGxGKHQclzZ9VO5+IvoBorXJWR2+co7E7Bn6kCrsaMccVeonIRkfC5epjgFxQ2Eul
         ZBGqjER0hgCx7dKv/YqV5k3udhTYPHzag8GT6A1Ty/R/cbqzHfeQFmvV8xxglARAmOA4
         hhgj0ZifmMNTkJMWL9XUgyiKGNO1Ej7UvzTo0kcBAl6NYtbkrst1jC5FHXdIElQP9X0c
         neoI3CUAvUsAT8IMSpoh2ZDom2JCaPlIK3T2Y8O1sDcuC1FHmNQ8Lw7i77Lhekq92gTK
         eRbq2PrIhiTbbgmICyMPy0Cal6ScVssLBJ4zJADHi/MD2oReAGVpEanVvetFhRcKaDDk
         yYCg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729084701; x=1729689501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Hn9yBFZWKU9rCR8LGmpBsb5Z29tVN2THo/euMT6UNA0=;
        b=XeyO/c4q1iKCxM8jfIxbQGz5s98sS1mTPpzLnh7Gd/j0qC1GaUIUBWRmce4SLlfvnD
         ATdX+m6WYVs6reD81lUOHHpxhb0jeGbzjVvATKoE29Zizkd3pyG3Xid8U9LCa/LXlEa5
         OVtsEhrJb+01ozKk5ucUoLbpEWdHcvNDjVoPqjxvf0UFS5K00U0yccAwpgAiB6YK9Bad
         pLXH6FZwF6HBz5K85QT138Andcbr1JN9L/yLC4qfG+vY7hmlIAkqjjD0/00j/Q4B1KRL
         MWTcWWCmIjZFaAugP0oaKP51PsuUNw5Dv+GlBOqzwjKS2/whniOL6NmeYxZCqJSZfX4O
         r74w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729084701; x=1729689501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Hn9yBFZWKU9rCR8LGmpBsb5Z29tVN2THo/euMT6UNA0=;
        b=t2PZWMsjsP5poThNTuPNGL3auQTHPSCkKZcFBeq0LpD75JxAIkBWWvtKSf9DI+MUDG
         wfeVYBeZZV+pF7K9PCkL3Lv4VA4D7cL60GlV2DNRUaJXoRYgDO33fESyNHyEStI9aj64
         Yx9qRWbW6uCqPPCGT3NvrcohLScurZ4HupfaYu+iFv7YOm9qvqwRdOu6XifHBrloPXfj
         pjEQajgx0euMAUmM8U6S0VExq8VocslI6l+HSH+BfWNn7R/JMgnvOTm5mxGyskFS6Li3
         jQWpzk4YHZtl/wyEvowJZLz6BCF1sZZTXW347NrErjdHbkqKEzUV0r/SbD6w+ARot1ih
         6RkQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXoDSQfGA5s1Qi+Z44SaybRV5KTY6kkpFzC6tLzNNpAzJYwu5geDnxEu3Gpy9xUqgt0qoIu8A==@lfdr.de
X-Gm-Message-State: AOJu0YwsagLLRe7qel3TDAwLkJqq67898HJMQbuGjtv1wawLlJEYTFgx
	JnyULP++cZovr4volqj3ndpVBVVDCzFdyl/IV7aQnnH/vuHSlkKV
X-Google-Smtp-Source: AGHT+IHocOoT8K360LWOeIufg3AzRCxeNAoEdcjlUAdlxh+ihrGX7w/TXLP4nlVtzNnlLQjVy6M9kQ==
X-Received: by 2002:a05:6512:2244:b0:539:d22c:37bd with SMTP id 2adb3069b0e04-539e5621de9mr6941833e87.36.1729084700674;
        Wed, 16 Oct 2024 06:18:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6408:b0:539:e021:5376 with SMTP id
 2adb3069b0e04-539e021561cls25405e87.1.-pod-prod-04-eu; Wed, 16 Oct 2024
 06:18:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwVe9oLCEilTsse32xtq+YTs3xXsNTDa6sdOGZDU+/1th16y/ukuWHk1ipjmA3weYVYHWO8NSuLdU=@googlegroups.com
X-Received: by 2002:a05:6512:3dac:b0:533:d3e:16f5 with SMTP id 2adb3069b0e04-539e57316e4mr8189605e87.38.1729084698536;
        Wed, 16 Oct 2024 06:18:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729084698; cv=none;
        d=google.com; s=arc-20240605;
        b=hJ5d/yjS4UCwVx2OiNJ/mIO2re9PprqwLnD1dsAOzWy688PPoRM9Ay4AUoL5YL8JSO
         rCJ18NIfLuB0M3h1tEARnZeRm0Ym7GFOcHgG6KV0HrbWU5G/t5c+dcWkdvWUdSBehwGx
         28CyQQWryqwUgcQewZjylb990ZhHV8CBlk9y/wNMGzYnGzx2Lnc9WJblmHY2WNvYM6E0
         9R/Syj0thzgpFXLpOhSPpiOF/oOow+t7gWPRjsFXjJkCeLrUVS1sHH1TsIXEV3qY5dp6
         KKLJFfEYI3gx78tcDmFni2ReI59y96enKoV+pww3uGg10Z9RfeUTvaUX4OvZkES/wdfp
         iOOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/8xPPGnp2eNdFzyDsH77udpuxb5hGHHiKYVsaBBQcww=;
        fh=zA5Wfc8kTI4FEbN12meXxPYWCkIslEXx0JNTKtbvu9g=;
        b=Q+bJszfzglAl3aK22SaVf5w4hNd0olM/x68RYxJGYGcUWfH2Mhxu/9NrRBrPcAYkH3
         TV54azcwUd570SmKOEAxe+6obwPhlkHWCDFqipznGRBDsrUcm1bstswrQw2oJjruJa7Z
         ZV6ngvg92sUw55cYD7W7L6dpkGnHDzgDQh1jGSnNku9PmPpfXYJgTCFCJkQQ6640C5BR
         VHiXa3HsbmEfRXImRaJx5nR12opUcORaSaS5nrt/c95Ig9aIxeq2h32KlJTlCMw2V7g9
         sOd1pUFSp2hcb36+fgECPBxSvA5hPsKybJmXb2KhP+YoefmrdHjL2ys9Iqr9bVgx65fU
         JgXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=b9jMqyRM;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-539fff78794si62627e87.0.2024.10.16.06.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 06:18:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-431548bd1b4so3783135e9.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 06:18:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU166Nd8EZQfrVdLk68YBZm5lLp+5/Y/CCXtnQOf/Rg9NQi5Fpq94Pba4LAhEG4ti3TITgal/GbEwE=@googlegroups.com
X-Received: by 2002:a05:600c:4fd3:b0:431:5503:43ca with SMTP id 5b1f17b1804b1-43155035333mr7296085e9.28.1729084697677;
        Wed, 16 Oct 2024 06:18:17 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4313f5698aesm49612825e9.11.2024.10.16.06.18.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 06:18:17 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: 2023002089@link.tyut.edu.cn,
	akpm@linux-foundation.org,
	alexs@kernel.org,
	corbet@lwn.net,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	siyanteng@loongson.cn,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com,
	workflows@vger.kernel.org
Subject: [PATCH v4 2/3] kasan: migrate copy_user_test to kunit
Date: Wed, 16 Oct 2024 18:18:01 +0500
Message-Id: <20241016131802.3115788-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241016131802.3115788-1-snovitoll@gmail.com>
References: <CA+fCnZf8YRH=gkmwU8enMLnGi7hHfVP4DSE2TLrmmVsHT10wRQ@mail.gmail.com>
 <20241016131802.3115788-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=b9jMqyRM;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::32a
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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes v2 -> v3:
- added a long string in usermem for strncpy_from_user. Suggested by Andrey.
---
 mm/kasan/Makefile            |  2 -
 mm/kasan/kasan_test_c.c      | 47 +++++++++++++++++++++
 mm/kasan/kasan_test_module.c | 81 ------------------------------------
 3 files changed, 47 insertions(+), 83 deletions(-)
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
index a181e4780d9..382bc64e42d 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1954,6 +1954,52 @@ static void rust_uaf(struct kunit *test)
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
+
+	/*
+	* Prepare a long string in usermem to avoid the strncpy_from_user test
+	* bailing out on '\0' before it reaches out-of-bounds.
+	*/
+	memset(kmem, 'a', size);
+	KUNIT_EXPECT_EQ(test, copy_to_user(usermem, kmem, size), 0);
+
+	KUNIT_EXPECT_KASAN_FAIL(test,
+		unused = strncpy_from_user(kmem, usermem, size + 1));
+}
+
 static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
@@ -2028,6 +2074,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016131802.3115788-3-snovitoll%40gmail.com.
