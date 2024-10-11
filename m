Return-Path: <kasan-dev+bncBDAOJ6534YNBBM5BUO4AMGQEQSDU5MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F2A9999DA5
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 09:16:06 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2fadadb092dsf9155641fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 00:16:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728630965; cv=pass;
        d=google.com; s=arc-20240605;
        b=apmkIXDEjYlryKq+E5VSTHq1Blh8I+RuFAifOIomxxjlECLXL0+nXZnOjxu6IOAQii
         zJd0EWB2qiud1xyd3Uv47sb/mZAYmSz9bZZw0x/M1LQnJEynY4kPNF+9Uura0RmWVnJg
         ZolV2rs3vfMquG3WiFUTI/npycr15i55zjg+eWynFgszxU62FymXl4uZbE6HOeP9D05l
         2NZqwsJh8JR+UdJzsdHHNbsGGQENOP/RK72O0icqiuqpQ2lrNxj+qTkYP/KXu11/sZ7P
         DaEhBDWh+7wemap9nmloaGKEVHyPQEd5Rk16+h4riQ+7sHi7bdUOlXGenlENb5sAOXZ9
         72Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=OE2RQwn9/cTHKxbnpq+zp4zoN89CXBLu8GGa3qXVMMo=;
        fh=Gz/IqN/UMfeqjzdzvKdNRAGu75Rwo+x5rytXcoIvK9U=;
        b=NEhE37eOLrryMC5R9a1NHOJgN+CeZqcaLXyKSNQJUIgGsPHQvRtUMQLB8I4NRyFeOL
         OFjExibKHcMP0o2OpoHqqCaQD+dTudHfRevFO+XoX10ZuCd6KjSfeN6kX7Ynwt2vx7yf
         tw7E3voePI6v7rLzmXceOO54J2Bg2pZKG83kyvQ0qJxGg8NQJABaEcb6+4bRFMypNmia
         cY1PRN9Fqi0jPuw6DfyknMxxX39qMvHMf1LFRzOnr0pkMqCmm9AWp1Op8MvIBc4k1LFH
         Sz3zVZg19PL/9tHOupU3HvKMwareY9oufQ2mYiXhtNb4YSygKXxTyYMzawEnO8OYa707
         LTjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FXRfI2r6;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728630965; x=1729235765; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OE2RQwn9/cTHKxbnpq+zp4zoN89CXBLu8GGa3qXVMMo=;
        b=hjpvs8Ey6gpm4zR7c2BTkRD+QOt6zPom0D4elILGZocV4wtEtSfCwxtVhCIS32kHmd
         nPHZ0LDqPrOt/WMegzGZVXuJqa1px/T0zPaMM9PqrJSOiiWsdxIrbqoIz3r08vpOhb0E
         YwhurJHgMzUKzCb8sCwHKBgiKjmo8ipbVeu8O9EgToOGngOKUcfjS7blhomi3bn4K61K
         bKx8tX2UQWHUod0Xkrj2eJiNpPKNccxMaZcQFBzg4k91u6wi+NwNKG4MFgnSsL4GQoXJ
         bOUOwAvtyzpXcDjlHIPc3T74haYcLjrBtjqWzV6FVkVdJqMszMzfkq5yubOyH+QUNgOH
         kEaw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728630965; x=1729235765; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OE2RQwn9/cTHKxbnpq+zp4zoN89CXBLu8GGa3qXVMMo=;
        b=JhAtb4yNmPu+VO6HGBOfaRRH2jh//rxvzrkGrE2HOd7Jyk1+XgB7DgiU7j80skgUPq
         GeIpum6N/gOQJRoDUnXoPWuNZ9RbK7XgfYGbi5Pb2CFDdMQL7DobHnfnHQa+zmXj0IIP
         GUAojZtGIntZuGkyTEUIXWG51EnRExMv2VWRs4U4BW6W55mv0lA4yymEVlhPhQU2rD+7
         3qGiMtSjrT+TGy3XyPTeqilqJ/wJhxdeL+r6sOJQpR/wpr3SW3MULKRmqSjaeSs1puCY
         Lym6G21VLnfX5uCsWLLTg9TYXYqbvnqS9ncIs1X8Yulklae3WDK9IoFGQFJxfbdwH14Q
         mTIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728630965; x=1729235765;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OE2RQwn9/cTHKxbnpq+zp4zoN89CXBLu8GGa3qXVMMo=;
        b=YiMUhwRdS9i0/MdmNzx6sog/djcelEXjCY+FxFBCUGPXtvbXwnyA5/sX5WRvTEemq9
         zhpsBg/hYmzMLY6mVByG2ZkA59lsPEVV57hbZRgOY2d9+Q7n0dXhrbaJoKzGoy1AO3yP
         7JjdD9BQhHCXrGOjrC30V4ALmK0885PSePWEsR0w9m17L+6fP0vVKuqoQbTAigVEq9DO
         +IbuGONz4m4fOFFJgti4S7BCDoSvpR1nGLksabRoyLZt+fFE6TiyNkTKdl+c5m802dC3
         rCeJ7dSsF+spiefiN5kOXY6GVTYsha5DUQ8JgGkMQ5uM7FJyd6ALnaAZirIbwJc2nhNi
         M6zw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXe8iiO2pUqEUtO6ASK2878b09TjZ9igeFr/0mBWZWAZ+grRBCBKS6O+EaLkxiEdLYykABang==@lfdr.de
X-Gm-Message-State: AOJu0YwDOMliDNoxCMtVLG7CqR6KGxhaj26/lhNwPyLcqulSWYthEK+Y
	1udYy+dmH0vm8bXj8QaiIZqL2YgVNBaO48aus18qnJQlgiEA1zDo
X-Google-Smtp-Source: AGHT+IGOklw2v/Q9HDHbi7flQpw2QubSfQGOS6IvjALjhnIl9HDfRnWzrWCkJ2EIYje9MvijTbXerQ==
X-Received: by 2002:a05:651c:98b:b0:2fa:c185:ac4e with SMTP id 38308e7fff4ca-2fb208e5e51mr21568581fa.13.1728630963994;
        Fri, 11 Oct 2024 00:16:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3e02:0:b0:2fb:3a87:c904 with SMTP id 38308e7fff4ca-2fb3a87cb2fls167201fa.0.-pod-prod-00-eu;
 Fri, 11 Oct 2024 00:16:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXG8P/7PUEMPw7G6UPYnVML7WGVjDjifRaqN5dSCjYVucpGeBTTDt3J2vem5FFbLd6EfIvNR6YllyY=@googlegroups.com
X-Received: by 2002:a05:651c:507:b0:2f7:6664:f272 with SMTP id 38308e7fff4ca-2fb207cafbbmr19622881fa.6.1728630961816;
        Fri, 11 Oct 2024 00:16:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728630961; cv=none;
        d=google.com; s=arc-20240605;
        b=YoIpUoN69uinzv5kwgbclvcGrwWeKFVDLFu1SvjC8lfURF1rxiLSEg8Xvh6ucpf99h
         tM4QC2hT7vj9JWNLZimMW/ISq0VmHqrDVi4oj8qlzpddCdY31HxJk3Vvg+RCcGOjjkbk
         czpi/wKccb02oRfwe7JKTnfsyk0JezLkQUapUeVR5198TFl1bYKgHzM6vOap3KbOAaFK
         2wHsK79SMG1dy9OIulEXjr/Nag1+jzDMGLRYqQqHdT2A+EPFspbWxDho6JJJu4EUPJtt
         WOg1cPfHXkCBNjz0UyQhrwduotsYPBxcnMRfMEXOaX000W806V8HRYUK5dHbqXazj56A
         SHGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=XCjVoezSoJ9cXRJsoOufBJfIeNbu/4t5Ob362xE6LB4=;
        fh=af+eZ4alpOkwFa/nNv42/CiF0vyE6xxdIJGXRHzxibE=;
        b=DVrHxgcL3Smm2WIwglyHybCwYRt5df8qlj9XjabdJn3acHvwuAwNSCmdXBvxCHetg8
         BDQcBIQBhbCM91IIIzhmeGJbD7sdvGMq5FBCwT3fsRYQY0rHbgYQ8UNojTr+zr1x1k/x
         Ty2RLuwRQsfD8ilUdTHJBylnjZV98sVKNOl3RLqercCMsnnAziwNpMFZOSTV+gcn6CMI
         rvzyf7Sqrk3240ro4N3DKCGvm3VwC2PW9Ou6wnQHBD0JgTAz6E08GK5Oupk0XeH/h3hb
         boCQyPJu4aTkPpDz/4N5qHTAvl1XfuqC1u2W3vWeCBE8KmESwQZfmqeFMIgEAO7rpSOH
         dKGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FXRfI2r6;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb2474c5ccsi531171fa.5.2024.10.11.00.16.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Oct 2024 00:16:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-2fb2e21b631so6712961fa.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 00:16:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUSH4v6zTYSOVbK7iEp8igXAfagREl86E5G0QPL4r1kVGIrLJtgqdITkvLXiwsTF/6uCMUmpbvsKos=@googlegroups.com
X-Received: by 2002:a05:6512:304c:b0:52f:36a:f929 with SMTP id 2adb3069b0e04-539c986474amr2004231e87.4.1728630960909;
        Fri, 11 Oct 2024 00:16:00 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-539ddf85cf4sm93946e87.68.2024.10.11.00.15.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 00:16:00 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: akpm@linux-foundation.org,
	ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com
Cc: glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH] kasan: migrate copy_user_test to kunit
Date: Fri, 11 Oct 2024 12:16:57 +0500
Message-Id: <20241011071657.3032690-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FXRfI2r6;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::22f
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

In order to detect OOB access in strncpy_from_user(), we need to move
kasan_check_write() to the function beginning to cover
if (can_do_masked_user_access()) {...} branch as well.

Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=212205
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 lib/strncpy_from_user.c      |  3 +-
 mm/kasan/kasan_test_c.c      | 39 +++++++++++++++++
 mm/kasan/kasan_test_module.c | 81 ------------------------------------
 3 files changed, 41 insertions(+), 82 deletions(-)
 delete mode 100644 mm/kasan/kasan_test_module.c

diff --git a/lib/strncpy_from_user.c b/lib/strncpy_from_user.c
index 989a12a67872..55c33e4f3c70 100644
--- a/lib/strncpy_from_user.c
+++ b/lib/strncpy_from_user.c
@@ -120,6 +120,8 @@ long strncpy_from_user(char *dst, const char __user *src, long count)
 	if (unlikely(count <= 0))
 		return 0;
 
+	kasan_check_write(dst, count);
+
 	if (can_do_masked_user_access()) {
 		long retval;
 
@@ -142,7 +144,6 @@ long strncpy_from_user(char *dst, const char __user *src, long count)
 		if (max > count)
 			max = count;
 
-		kasan_check_write(dst, count);
 		check_object_size(dst, count, false);
 		if (user_read_access_begin(src, max)) {
 			retval = do_strncpy_from_user(dst, src, count, max);
diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..e71a16d0dfb9 100644
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
index 27ec22767e42..000000000000
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011071657.3032690-1-snovitoll%40gmail.com.
