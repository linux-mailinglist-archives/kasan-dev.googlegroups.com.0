Return-Path: <kasan-dev+bncBDAOJ6534YNBBKE6WC4AMGQEOLYAYCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C8C599BABC
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 20:19:21 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-37d4cf04be1sf1647200f8f.2
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 11:19:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728843561; cv=pass;
        d=google.com; s=arc-20240605;
        b=IUlsQQWzHxctyR9Dk43MUaBz49yia/6ZF6AADyQt2l4jcNobRXj7/5LIEnGs5Um6CV
         REFi8gBJ0mUCos577atfAct9WFDb5+a4MwQ4WbrsPdk4V2Q2+WpHbkvVc6W3qxxSGfmM
         feGx43ujYIAlEW4u7FCa4+xloZiUEw8vB+VpTonG+YeOVrMDxUeaa4QlLs+JJF0fUfeO
         KQb4gt518IC79eWWQyDfIOt8hHKIT7AKzDyQrMvCMgRGdatxu8pL4k5Ag42EvFt7kjDR
         DEGi0/ichheH3hpFdk3jwEkDLxuNbCFSnIa+5c0WRdLHHFwa826CPO/rKRBjtwgopx/u
         kQ6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=h3loQUzJ9udXL3BPAWf4fgk6ZwYbt40CNi7r8oqnOrk=;
        fh=ancYYgpw8AotO6zAIEZGO7Rmw8VQBg+8kKqM0gtDTWY=;
        b=dKDhq8RfYJ2O0AQi+EkPIJjlAiKhuJnBsDuY1KkTgIxH7TCDKcvsd1ZIN4z453OHP/
         V01LCgPyZhgyV6icA8RwzOrlkP8WWLkxnwr53/dd+U2bp+w175DogC7o/t4mHcQNrGUj
         Uf7DHkJLyLS58+vw/wiml2GQkjVIAgIcoWxOJmvAXV6lGdgMPnubT5C6RkJUbTXCjeiV
         Zyo0m6ibRdGeq4+6aX2aP+wA2UFKUgqgRFo6tuG7saVb/eSh0BYAI76ieW5yt9CKjS2G
         XvMIGidzHg/ZTYYWbOmjfSgUlSQMYHeaHixp2YWA7ykrMV/4yF7QpCeO2mf3CAG+RNjN
         VNng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a0dofgGn;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728843561; x=1729448361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h3loQUzJ9udXL3BPAWf4fgk6ZwYbt40CNi7r8oqnOrk=;
        b=II8zHKwVq9Y1FH6MP+sCh3M6lCFEh2PFsyT2ilf1ONJna1N4jXIvOx6v7DIR3iy0B8
         ntYRBSjLuGUBFMT19P4HrEZnIqGO6pfe+hLaNUw4xr/9eo+y8qTgqTqEXGi9W+JO6kOu
         7SwsGmCEq17N8zHGHMUgzCUs/gNQv91PSOg22gTo1G9Xdl7SXVtj5F2JCFWL+1Qi2Xk2
         x0azfC1e4QnAZDbj6hLgY+KRie6JgZXfTyZkDleaQkHDOVL+j5Xjygi/keZNjrD0S5+j
         3JchwhFtLen6lfDtp/1sPjD+WVEVY6kP1dEQyPbST3boji5+DQXd+GREyLftdPIoesg2
         jY/g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728843561; x=1729448361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=h3loQUzJ9udXL3BPAWf4fgk6ZwYbt40CNi7r8oqnOrk=;
        b=eYqatGQmpXxNPecCaAvWBfYJpkXS/TZXsSK5v95FVLL6mum2btGboDskua9XA6HrLy
         ac6QkXqOcr6iX2KctmmjiklTvIeWyEYJCKzwRWby/8kt6KXTe8Tt7R04r6Fu3z3GfOOJ
         /1ao5vGaEjn+JAeZKmPtOHdiI4Gt+klaQacgYoOVIBVF7007f9ouZU4rP+vJhMoM3cDS
         ydeDn/uVJhtjwS+vxSd3zLX6kGNF+NhczJkQNd7UuaR8D4M9v88DR1p3GRASjx40VNxs
         XbU6SH/sZpq8AKwrgoqozZ0QTfSnNnTxCjyUozDQun8rA5PABv+RWkD+QeI0Fp1Luyk4
         Ztbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728843561; x=1729448361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h3loQUzJ9udXL3BPAWf4fgk6ZwYbt40CNi7r8oqnOrk=;
        b=U7tIS5zPi5C+LO2dh2Hc1HbOCTMl64gGxFamPZhVrcIDrge+VwSI2p5TH+/dY/B+gn
         M+IVQ0tOUDzKaPT11jc6fE9Owo672pSDWQJFw2G8yHqcO1hLSL4kv7JPcPW03QdZAVYL
         JvG3HOy810wyZlm4aankcY2K0o3XtNxIqTKQkyMPgwBy4UH5x85V3XcZDvzw1rhIuY6q
         a4pT498eyIctiJ31btXBJVnZ64i3J6Yz0HDEIgfkXYKL1BsSXAVwU7KaqYyxz4XY4EX2
         CA/puqQG7o7YNxVhYQccpELT0LNiKhIOW9pez4av9eipDkT2BqgOA4BOSlppJoCkZ+JD
         y5jw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1oIiq6sDOp48mKzCBtqXoHeyvApHkSHjbhKV7JIcqhIQINgFlQY5/dNENWE267zymMuHsOg==@lfdr.de
X-Gm-Message-State: AOJu0YwmY4YV7+ib3Y6vFCelRThrKzlVixjSU9SkGfXUjQrA0XqKg4PB
	hQsWj0/UjbLEJcbDbOZsTQp3JAoPypb5YAlN5y5hmoh9Td7JpNUZ
X-Google-Smtp-Source: AGHT+IFsYVP/vGABJWXVrn/mUtDbr9VdChuef/q9vcwHjLjKFgLuWtw8I3qGB/zljO1WgMfMD7Ypjw==
X-Received: by 2002:a05:6000:181a:b0:37c:cd1d:b87e with SMTP id ffacd0b85a97d-37d551d50a7mr6438805f8f.18.1728843560536;
        Sun, 13 Oct 2024 11:19:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:66c9:0:b0:368:31b2:9e93 with SMTP id ffacd0b85a97d-37d48235627ls544468f8f.1.-pod-prod-02-eu;
 Sun, 13 Oct 2024 11:19:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXk7Pq+lUgILQffQxv991LESyzOgZ4+hKw3EtmgGnfxyZ+2QfIHKf3RrDRmfMvC+SXuRQ9lAMR+1DA=@googlegroups.com
X-Received: by 2002:a05:6000:bc4:b0:368:3731:1613 with SMTP id ffacd0b85a97d-37d551ca21amr5332289f8f.13.1728843558703;
        Sun, 13 Oct 2024 11:19:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728843558; cv=none;
        d=google.com; s=arc-20240605;
        b=APTYVbJj8kniDTw06/kyBy+TPMOn8mqMIrYmKaCMcr3W7zsaDluZW/sO6VefZCbpgm
         ELBso5bCPb0MkCDIQVtuEn6GXa1cHacTvTlQaYDMZ90cXAGs6t4NZhyrNvjY34SAHePb
         wVMTcrhqd+V+yDZAcfRxsjL+nvJJ9wkTtfy2k3w2jjJ2x+TYmbPoxkbCelCegQkzDIZv
         BXyuzJ9kKpECE038+B0x2cta6aceubO/uQIIdYM+eHHL48BLpkpPfIA3Mq0RFYHZildi
         zHmXZd1ef4ACUbs2+d0+T5ibmPWwSbL/2D9JTFVKN4lQtLBVSb1qcevCjlUIMuTK6y8k
         YtmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=X56ki4zUkTbfkScVrmia1mDMQKgiUsSq+BtzwCXhyN8=;
        fh=Qt4XiSeMSJBgS6KibVrZ8UoTkITy3urIqb2KlUkTkWs=;
        b=FBc+ectM3AX+ASvZiaE9D6ahDtw6om35pbnajlxgFDlQ2QczKsc61C6KNyaHsRnHO+
         GKZ8XSYVNOGMZ/ZkXNqcZPyR9d+SWnIJENvJkGnF5Ns9y6b+yKT2FDVUNtvdR38VrP9O
         E6Bc4ujgFl5L4ntS1U3+EJVkX+W4ON+unaf90Y2n6eU96bcewC6vaP3vTtyLCNaYiOt6
         kCeQYU1jgsdF4RmTmJb+KKjsosLDIePd+x3pdQ53U2xVrFkDP4l8nRCM89Evea13hLyD
         w0HENCtvxng8QwOemyK7LnFxxr9DgpBIlkIpCtSXAfq9x5M+2ZDql2Ib/abd/mxCp125
         qF4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a0dofgGn;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d4b7c968csi130272f8f.6.2024.10.13.11.19.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 11:19:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-5c94c4ad9d8so2882821a12.2
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 11:19:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVejAiLBIOhoAQ1sIXxDhyDDNT2PA3zSugmOWcvqfykpn4tLMNIWJhBYY7zG3RZAr0LGC1HfsdusNg=@googlegroups.com
X-Received: by 2002:a17:906:fe41:b0:a99:c075:6592 with SMTP id a640c23a62f3a-a99c075952emr779610666b.56.1728843557929;
        Sun, 13 Oct 2024 11:19:17 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a99e57f763bsm249937066b.85.2024.10.13.11.19.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 11:19:17 -0700 (PDT)
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
Subject: [PATCH v3 2/3] kasan: migrate copy_user_test to kunit
Date: Sun, 13 Oct 2024 23:20:16 +0500
Message-Id: <20241013182016.3074875-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CA+fCnZfL2LHP7rBqCK5ZbsYu-jJ+2YbV4f0ijjDd_gQGiivNWg@mail.gmail.com>
References: <CA+fCnZfL2LHP7rBqCK5ZbsYu-jJ+2YbV4f0ijjDd_gQGiivNWg@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=a0dofgGn;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::530
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241013182016.3074875-1-snovitoll%40gmail.com.
