Return-Path: <kasan-dev+bncBAABBR6G2CEAMGQE4RKP5XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D6973E989E
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:21:43 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5-20020a1c00050000b02902e67111d9f0sf1176747wma.4
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:21:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628709703; cv=pass;
        d=google.com; s=arc-20160816;
        b=NuDaArZ1xC93Wo+DIOUgKiYCvl26awK8kjy7vuZxPDWeKub+zJ23fhpr09zk/J22xq
         5ZEsl/hr49MVGhA46x9nRL4Z4CnV8YACXpyGzOP4utllSy9CRbcR+M8896eAC35LPBbS
         lmR4uOaVQf8oacS0IC0SOJWMjoM5kuAbKgYjJGzFOkWVL4P+JAsGtJIZOlKePBCGEcw8
         npeDzSraMgXVgZISVJGktekMe2k4DfHgDy9DXAdPg3tnYMDCUZmIILwROXCJQHSz9XJr
         PegMaWgj/VLLYTxtp3RZa5zXGeZNqiQMN2Kscg49/EYklXE0c92nlVH6YJG06kICpKd5
         we4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3YU7lu2HIjvHatMrzdMIBoE7PAWaUshCiQMg/ri9zhM=;
        b=Ugo2LS0nP44cU1aY3fhiB5WVW2nMxXBrK1kPl4yCT/0j4c6mjtCQY0Kt3QNt2OvG+t
         h9+l66ftJIfAqk0jgdtxU7DLUIFSLeNTDAtkhUnhwCICzaztM5jZBHxQOOs94XYOpTp6
         vyVOJXbX4RiqTZfF/zrTw/kSkDRNkPdj7GvGP2CIcoEGRvNwhLocOumb7+BrgXOiqi6x
         BH7WXlwJMtRukKCU0C59+O+NNh1gFXB7fJkKiBlVQYuYHxnfOUqLRMZ56ohcV7L9yPh8
         XnekOzd7dDnBk1nClQL/fT/dDy2e3qjiOSWcLP32cHOM7gEE6cRnF7tNyb63QS1sUU+K
         yFFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZQA3DIJP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3YU7lu2HIjvHatMrzdMIBoE7PAWaUshCiQMg/ri9zhM=;
        b=ATl0f3CGDn0qBpN+i6T/bKqbBLln5+0rvNA6U04Ql89iyKHj04KGXC14mCPLPnH8JU
         IfgdR9NpVxArTyaM1boacTNpmzsv502OtXpD43M9TBdYebHsnIBbp0jinCpssWAsmqZy
         r2kMGrLdyIGXEBqlNSRzWo9MzC05r2v+fyPilV6aa6i/NAJIksWFUxz0pC+EXKOVyaGG
         JG8nfSr3eCnyXaTIeXO54wrkcEBt34lJ5qlHzu0HZbK31+tjW09Nui3JDJev8ZBEXuQb
         EAS0GckieWcq3AEFzy7JfAjU1aFnRm2ygnmQnAEFKcSjvTqj+CHRardV17kB6b/meN3h
         t6AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3YU7lu2HIjvHatMrzdMIBoE7PAWaUshCiQMg/ri9zhM=;
        b=M9rk+uez11gCotgQDSakvP8uH1EnKow3+/g5SA9/ARFtVIDSgCkhBoxbLDILa79VKc
         50LkFwLPSsLRpZBLsVW4eFg6LgDnVKeTQUpoybXgPAptbVwOv/8O1+Sv8SHTXOXFx6q1
         QOqlm0Q5rzG9sDTQgqbWQkZFb+wRQlrxIA4O5gDhux+W9CYXp+NifjXI5P+mYJXLXWLT
         K4JnFgOvPYNzxdfHNEoabghfxzGDiqAVwQBcJsjGISEHdM56367F01JqmMpzBQy5sKaK
         zCE9t8MBNKX6bGJnXneO+0aAduwAr3+BC9K5A6u0Ka9ZhefaZhG8mF4mgm5AnES1qBgo
         lGvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309b62amE92bgfGUdF1PAHL5jZGbJjCeiLAUKe1dAiZ8Su1GwqP
	5kvhLgfZd9QFt/j8Z7xytWw=
X-Google-Smtp-Source: ABdhPJzGkHixCv/1bRC+0xG3k6nY5ONLHFSZ2Vv2xxIb9fL7EMSIvzqcOscuekY4iy4JvmUbjejAjQ==
X-Received: by 2002:a5d:49c1:: with SMTP id t1mr20916wrs.141.1628709703332;
        Wed, 11 Aug 2021 12:21:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e5c5:: with SMTP id a5ls2019632wrn.0.gmail; Wed, 11 Aug
 2021 12:21:42 -0700 (PDT)
X-Received: by 2002:adf:80e8:: with SMTP id 95mr33093wrl.388.1628709702708;
        Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628709702; cv=none;
        d=google.com; s=arc-20160816;
        b=YlTGs0QdnTE9vOwE4GB9aOOYA5Vse+8p6lWUNMQYEcSFlg+3h7kc9MlxYBX1oYBWpb
         5b/otQukPatLRR7Tc7RZVbt0oPzut3/PC8iGn7qSIbuhc8lMo+CyizB1QvjpQggSTQ4R
         Qi4lXNyR9f/NCMegnoUfiNKoXIcvqwS35RndYyql67qlg2k7WHmdQNWjLa4Lw5NzBhjz
         i+hq9NM8ujt4AK17tyoMyW+v5nNKcU5IvJPccUZ7lwyva0IPw7ipDPOvkTmGFhV7zjpu
         e6bQXBtTmGHpnbDOqJeGkFZfjrRf3+op6eQMlWeSvkZ+hxkJKXcwxu8xugN8UHpSmhMx
         wUJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jkojDrgxIR2XbRn8TG52WE2ryFsf3sjf8wg3n6qSYXw=;
        b=gRYgtsJoT/pWQnFzGf/8FStqUr3L3vsui+eQEWol/9GIEVDpI9GL+puy+kq7SSJtbX
         BywhZJt47HtfqvUXO+AeY5TfAiXqzOrUSs1DeQatKxnCaxebEIbEQbtLQKqrxkPqy8cI
         qUnDZD8JPX2XMDU6iraKBmp6hQC64/h8otCaTwnuKfbytCYvvGqu9J3yZV67zw9hN2D5
         6OOLZgzOyvYU/NLZBJB3gQ30Hre3371MlAapPVYkL/YPjQOKvOhFCqXrCevc+OgFy9Xs
         lsmmkDUibHLjeepr68vnKF9cS0X0TK4cGrZ0rKJK6uTGsMsTcJR9s3/qNU2nnaCAKxKC
         vYig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZQA3DIJP;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id m33si15964wms.0.2021.08.11.12.21.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 3/8] kasan: test: avoid corrupting memory via memset
Date: Wed, 11 Aug 2021 21:21:19 +0200
Message-Id: <e9e2f7180f96e2496f0249ac81887376c6171e8f.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
References: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZQA3DIJP;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

kmalloc_oob_memset_*() tests do writes past the allocated objects.
As the result, they corrupt memory, which might lead to crashes with the
HW_TAGS mode, as it neither uses quarantine nor redzones.

Adjust the tests to only write memory within the aligned kmalloc objects.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 22 +++++++++++-----------
 1 file changed, 11 insertions(+), 11 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index c82a82eb5393..fd00cd35e82c 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -431,61 +431,61 @@ static void kmalloc_uaf_16(struct kunit *test)
 static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 7 + OOB_TAG_OFF, 0, 2));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 2));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_memset_4(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 5 + OOB_TAG_OFF, 0, 4));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 4));
 	kfree(ptr);
 }
 
-
 static void kmalloc_oob_memset_8(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 8));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 8));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_memset_16(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 16;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 16));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 16));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_in_memset(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 666;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size + 5 + OOB_TAG_OFF));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+				memset(ptr, 0, size + KASAN_GRANULE_SIZE));
 	kfree(ptr);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e9e2f7180f96e2496f0249ac81887376c6171e8f.1628709663.git.andreyknvl%40gmail.com.
