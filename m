Return-Path: <kasan-dev+bncBDAOJ6534YNBB3EQWK4AMGQE674KC5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BD24699BDEB
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 04:56:46 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-43129d9f21bsf7553695e9.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 19:56:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728874606; cv=pass;
        d=google.com; s=arc-20240605;
        b=SvnZCidZ75m2pXASXjNe/T8c9WBljENg88yM0zAmQLQCdyJZ4b8UVgYNhdn8U0W+ns
         xqDf/ckqHBnPkEHnDvhS1rIolvAUCxL9jcJA23LVMzTdQpHH0PTYfj3SpIv0s3q1kb5Q
         /7lOcVPvxuQYrl0aRnFwxng52utRoBvLYlPn4/2x2JqfJik17kFkrHpN2BdRxfIx7IW5
         GUKnD7QTEi8mCxbial28dKxEWl/0NKzesE86/W5odB1zjaZdgbHMi/xK5gpl+eGUdYlc
         +d9/p/QPzssYeohunTGOQwc7AKFoiGm8bYKfqDyCucLg9yOlhdMXQo5PIV8/z9UzMgy9
         8Rwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ZK5qaeOmsl4+ULJySJcT8DWUa+w6APA0UtkOkMrp+vg=;
        fh=zew0fWMERjZoZ+aNXuhEj3JgQKlu4tcc13yMBYzeQFY=;
        b=jtybhe5fZMYF4uqs4xB1w6tDJoKhCjBr9Yc2iHNzb5yX035xWQgg9afFE15b4ce3nB
         DocPhD88H9geGeTqfY5fAkxgX+zli8MuWIAI9Ar60k1lAs6/SSYIIz7LSfomgdgxTR3D
         FEw932eXoH4oSmbQcLz5eq3AqLcOb+d/Nymy61lMFrsFBOer+94UqV5pDyxferuJBtIp
         2Su9NVug8ykE2Y5szrYAt/pSWKbOAraf2zXpR63ivifplQAegFCvE5RlC4eXL5+tgwiz
         y1irVPxFxpGQQVvA2EU4WZxESutA6+A1P0IZjblmFyrhJ1Y06mm77SX9G+rhn0ug/+eH
         3lfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=evGSdOMn;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728874606; x=1729479406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZK5qaeOmsl4+ULJySJcT8DWUa+w6APA0UtkOkMrp+vg=;
        b=EjLYvq+TDHTC2nsQjSnArUpxOTYiNDkUlyVQQslIKKAjabfcPQyLBkbhAhXEiVaU93
         VF2wFMSPUuWuI+E595mQtJn05ZXjuW9IL1p33ShIPJNFH4jBs7+fQmwWg8nS65jLYBr5
         zx7b9oX+Ez01dClJnNM6ZNCboCQgE+FDf1bm+2vaRGpKwr4cR7iKbUS7N7PKmGBuOb9a
         4LgSchmh02T2OpoGqI8FNm8EguOUDxul/QcA8KwpHrV9qUvMsl+PdFiGnGNuY13WKRAP
         GcsgeE12m/Ts/f+Jz1ymq3+ocqY/QaODb1+Ybsl3eEBZKf/+DATDWrhAQ5mW+ttVlKSo
         D83w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728874606; x=1729479406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ZK5qaeOmsl4+ULJySJcT8DWUa+w6APA0UtkOkMrp+vg=;
        b=XmuzxVvPd6/2uk9H7+8kwGjcUvEJteymsZT56KCzhVz4ewm/j0Hv/RNSlRznZbz957
         22swCEHQG7jmcJDJKwhywxTtmJkT8DAUDOC6SCogdeOwg4W4FNDweuUuDhzRafKsP99M
         TTMRNYltDAqgtD7utvyEToUX+irvnpjOf1vIoZ1giUfvrGoHlAfqoRYTMVmQntL6BBWX
         2IJm+FLueIGtP4gwIDn56D5CO1jUE0WhxsNYBt5aeYnNJEYKeOtmhinygcSxvof/nD/D
         dbT3Q28XviUE/TsQt46Mf5YT6rCjyn3HFyNha1Y6YMZy5boov0xkpXyKBJ50AuAu5CM6
         FZpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728874606; x=1729479406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZK5qaeOmsl4+ULJySJcT8DWUa+w6APA0UtkOkMrp+vg=;
        b=Z2AaQ/K4j5NZ+eHjGSs9/9V6tEfdhlbKBMnBB4hiXZcWZK6ofN9VdB3dqXMD2nO4Ot
         8quLiaMEGnb1Wlt4rCpQBZx58m8MnSwhCZPTASLTQr4N1U+VlkacDt6a6rNXgW0YsK3v
         icKdDL+nLHP1UqOhoKqinYm0kmMyA+7wXIEULN7T5XpRgIPnf4MWNWCp9Z+N/uUY1oct
         OunfEdWhvK+OyoGDsPdXKyK/iP7VifpLzSDbMzFYjmpSZVY5Hs9RERKo4D/zV3ogk7x5
         rvne07jojIaul1XpUczsRtIc7AdvH34nPSMPtnuQDKHrl24JCDTCTnoTM1vOVGV3bLuC
         nghg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXCN0XVFoKxeVdfZAjOQlhgm1K2lKIm+22fJMg6Lgu6IJhlDHlBDmN1ujF+4dss88i+vzRtAA==@lfdr.de
X-Gm-Message-State: AOJu0YwUhyXcLS9Xefoao3qE/IK4FOENowTGmUnooq3dfDVN6+5tHMBc
	A1wu+sk044YkTRnMFg9a7URgxOEY3jYitp2v9qdR2SN6gf7Y5O5c
X-Google-Smtp-Source: AGHT+IHYrgHDZyzdhOP1fHuObDXbdiZDTyKwfSSroCYXCX8VRFtwGM00pYh3Vhd062Id1t+iVaviag==
X-Received: by 2002:a05:600c:5250:b0:42c:b8c9:16cb with SMTP id 5b1f17b1804b1-4311deae1b4mr99123275e9.5.1728874605109;
        Sun, 13 Oct 2024 19:56:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5121:b0:42c:af5b:facf with SMTP id
 5b1f17b1804b1-43115fd8918ls7641435e9.1.-pod-prod-03-eu; Sun, 13 Oct 2024
 19:56:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+Ox9PAdDMNivd+PGchbdRhtOlblC3RreBgxYOU+p0ZAm/7s23u06GqbwRfPJ+aw9mjeXvDymOLJA=@googlegroups.com
X-Received: by 2002:a05:600c:46c9:b0:42c:b3e5:f68c with SMTP id 5b1f17b1804b1-4311dea44a9mr74907655e9.4.1728874603375;
        Sun, 13 Oct 2024 19:56:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728874603; cv=none;
        d=google.com; s=arc-20240605;
        b=GXMUyNIJGaahlxeMJm6E3oJr0FKqyXFUU0h9oFGJIKQKLqVGLAhd++MO5ypEIeFYtj
         y0r00iILtJn9QStDOYCAYVXzuRWzQwQ3W8//9GwSjtrq7HzUfxWJk3CASAghyjsRHqj+
         gqDMwHPkvR0ifMU9ByC6pWF8XOMH5ALDwTdntGL2jx57Ub5I8EExw6lYcTp3omRv5xvS
         pN/sQMVArLcm6vP3eqsjtIXw3Xou+ogONHAGDptdcLdhQyp3Tfg6E4pJmR+dnchXmXzd
         M0sDwhteFe3xnxOepogV9qItrR1wXs27k5uQBi4ili6cEuOJhCOEcwd+AIUv202Ecnav
         AVcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/8xPPGnp2eNdFzyDsH77udpuxb5hGHHiKYVsaBBQcww=;
        fh=mMIRKYyww//reH1o7wqv/QwoZclCXOQvVO/HB8e/Ygk=;
        b=Fmsj9Mtj/mWC5dQc5No/8XPLIJwOeBcmpkWgMQiJ46S9iVXE2g47L0cmSEsy2JdY2U
         pExc7+cg7NREEv/FWiDlxUpCLSEPFSmg8azkwfQ6r+KTNH6nPmYxDwM6q8j5Vss7yx/q
         1PDh/J013ni1tgcgJxXaar+iqxL7XphUIiqjpiPSo4dS+04ef3Df6eCfG2hbNVp0jYqZ
         R59un53lf8pLGotAAA5m0yofoVdHhHmSVblq5/kwEv9bfId7I+1CZHepmb4wSHtZ3d5a
         MPIAVQOaz9AE7Qp1cq6zOdT/jlQziMfs/wDF/VO262zA24dYfacBIwb4utJQFJTO+Bop
         agDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=evGSdOMn;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-430d70b47a8si2231845e9.2.2024.10.13.19.56.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 19:56:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id a640c23a62f3a-a994cd82a3bso560553466b.2
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 19:56:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXmEEl4ZfcTJ7RgY2isjocpdznRtUsevo8RAYmbc3yqvKm+EgMEGg7xrZnMjChHwYHu5QET68BJ7DU=@googlegroups.com
X-Received: by 2002:a17:907:9488:b0:a9a:791:fb86 with SMTP id a640c23a62f3a-a9a0792046fmr282817966b.64.1728874602739;
        Sun, 13 Oct 2024 19:56:42 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a99ebdfbff1sm270501366b.39.2024.10.13.19.56.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 19:56:42 -0700 (PDT)
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
Subject: [PATCH RESEND v3 2/3] kasan: migrate copy_user_test to kunit
Date: Mon, 14 Oct 2024 07:57:00 +0500
Message-Id: <20241014025701.3096253-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241014025701.3096253-1-snovitoll@gmail.com>
References: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
 <20241014025701.3096253-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=evGSdOMn;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::62d
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014025701.3096253-3-snovitoll%40gmail.com.
