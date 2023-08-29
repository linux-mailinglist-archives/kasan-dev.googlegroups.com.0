Return-Path: <kasan-dev+bncBAABBCWOXCTQMGQEA23KFUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 93DFC78CA5F
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:12:43 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-3fe1521678fsf31067795e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:12:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329163; cv=pass;
        d=google.com; s=arc-20160816;
        b=JUHkmvD42L0xgcPhIcLdlzQBXwo9Cn08DY2n2PQiP4w/Nxy2VgZws+uuFRpCdq+wHc
         szEkmU/tpZFagHyd1ibjLMfw4mDvyQa/stKSyl7pyP7+aDfKTNk1eDFb2ntQQ7W6cPSB
         rUm54f3uAKGpee7MvQOsaZyGwv2RvWA5uKUdqYCR0JjopZX61qW9doxGzyIY8e0MyM/0
         2SEG3OX9dGAR5TzdHXxmnv7NpE5JeTg022ryMPj5klGbcBjOoNaqc8p6kBbjAtTi9n1y
         bCG18N8bPeUqQ/uRAaAyJaXRFgbL7MnGaBrTlLgzTKMYiz/yr80Xd2Fbg0RYjyJL6jF8
         wlDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=e2uQ0dSDnh/P75NrTlwPowguHXtyUhvAPC1C1r4ict8=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=AYxsQTHTXRfUjYmnPW5j7UqvvHORe6T4eLerO1BViEmqNFbv80GtRAFf5oJ4Zs7P6e
         ugOhL8gVER3FDHgfa2bCVapqcTctSVdPkepR+utmyZxs9IZQBn5MAFwnJn2y4/qnBVNZ
         MRdiqDU6mDwxwNDnWa7B8DZFq5+CTjMp+bzydc8MT4mPbKYmzZeqhYDWfL/yy8/kXEOb
         8ZIH1gjHDJxdfCqJy827+kTTUa4tgUbQlWIsxd1s+uX5+dpMfqJEvvCR1MliJAhC1qI1
         OpwnKHnaoC1j2doQR25ppHjfFLsNtD8p/rpY1i6YE4ZSyqSg1Nvigxg0Jp+CHJEWzR+T
         lqaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tY6t+d+v;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.243 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329163; x=1693933963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e2uQ0dSDnh/P75NrTlwPowguHXtyUhvAPC1C1r4ict8=;
        b=j09KPfSHgv2c9hXy00un5Jyam6oWGy1rxji48a0wAUzJAIiZvytThI/Qt6hu84EUR3
         SrugQ+C1MbmJLSW5uqYgmmJ39vy+emzr3ANT3MV9ZYjqJ71qn1mYPW5/5DH3tqbpcRRi
         gnyxDlZLsrxO1NbuRiNtZsvQCIJC35vuKyr6t1YEZPQPZ3VwwA5e5LM9Uj7HycXLLusn
         f6thMDuFq9QLtCc7DzlA9JktbHjW/EQ7A7a3KS5TVHE6D5azpBrTQEfq3DiSadO351ng
         kh98nOYiZV7AfAGKEm57JLksDHusZOK1FrYiWn6O0/ZO6BNT3SDCL0Qo6LRT/pn1yLJd
         /meQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329163; x=1693933963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=e2uQ0dSDnh/P75NrTlwPowguHXtyUhvAPC1C1r4ict8=;
        b=P9qxQI9UIW4SRPuM2cjucHqhmBGyzRW+xa45p/YqdkP3CA3eETYL578XSQ50OS9nDo
         L9tSyzvEzuSlYVH+pkV0QvBEQQBmwgpJJ/ObK//04NuhWzSqsqWnI3+NwUxjpD1SUc7n
         /PwMmp1JVINGbq/31hWgeGP97/pum9uQxAmQhOGysVLpgzROINYDHHRyKESf3nFf7pzk
         3t8St9ODub+ytM04MWsKdJzlRRRDdq/QAWUb97Yy0du+eG5hwExNQsRQ0lZF6WsgaB3x
         DVduDd1Kgz1UNrjsd4qPWGSjMfJ1Th1jTg2A4/5fcwPTrlo0USBkPl+qZOxsoFXtzsUR
         5EJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxghJDAhqL9axYVYfOG2Z6etK5okLqdQwLric8iq2LJqw45uHGa
	N4bP6BTASOuQAPbBtnOlvR0=
X-Google-Smtp-Source: AGHT+IHWTTNAZFPWWZ4MNB5BdPtURD3Mrem8c58WPkU5yeATpDRhkB2tqgbacszKXgv1TG59lldfKA==
X-Received: by 2002:a7b:cb85:0:b0:401:bf56:8baf with SMTP id m5-20020a7bcb85000000b00401bf568bafmr7438737wmi.8.1693329162925;
        Tue, 29 Aug 2023 10:12:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3546:b0:3fe:1974:f893 with SMTP id
 i6-20020a05600c354600b003fe1974f893ls2141024wmq.0.-pod-prod-07-eu; Tue, 29
 Aug 2023 10:12:41 -0700 (PDT)
X-Received: by 2002:a5d:5242:0:b0:319:7230:d76a with SMTP id k2-20020a5d5242000000b003197230d76amr25214237wrc.38.1693329161605;
        Tue, 29 Aug 2023 10:12:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329161; cv=none;
        d=google.com; s=arc-20160816;
        b=TB+2vynELBudbvJJfiEc/Y+pmsog4z7akVR3cuQRTTXBPTYi2B1/eo1wXIDuZSJr+N
         hqTnsDx/GhD+/3EW7SBJwH/2v+d9NFdjdE3gKGZ5CyYCRqEw6RbrJzyVHmTPhFxOH6Tf
         z0eXCMDIgx27pbiFxPU4RZZcaZyotk32hZ1aw3tfanX4ZVxN38ZdGJ9bmEgjewqFbm2H
         qNbajyUAqg2psb2knlteZQl9D6oe0p9QPljS0zBrBGQAqLkvxspjN1DmS/osBpze+waN
         foeVsQurKBbTuEjbqTNorMdJ4U2dJlvpSwOOgmnU0aPgh/AuNLp9Iqm4rWQghMnRZGvU
         ZKsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MjxW8cEdQiVOI1Uv8f/KLmoitLM15XxpvrzjQCh/NXc=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=n+AYw32uh2NGG1TfMzUFpGzx/3QURoJN6PBjqIqg4XUEBPYjjvd8KIMRBGnwvdbKo8
         j45IIah2+6LZC/ShueW59Zjj2W2tP8uKgD3BeXgKUaFi3CJq8PxD5ZMhuNCFtDnhuhvb
         3k4gXN8S4CQRdOBO9CFc1BuP2agADerCvux0dxdWU9hD39+azY/3JXfEpES+TYTM08LE
         5QMiSm7tqZwChDlfYXgu2LFK4INXpP0FVfWGBfYH4mwHLM2tJK8fkbsomXihQAONhtH5
         uE8PQcbguERQ8K6VwH0ByiYvZI5eB2KDdWJaWUNwPF6DrhV/U1R4pMzc0J8MvV+e63cz
         4WHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tY6t+d+v;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.243 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-243.mta1.migadu.com (out-243.mta1.migadu.com. [95.215.58.243])
        by gmr-mx.google.com with ESMTPS id i22-20020a0564020f1600b0051e6316130dsi766978eda.5.2023.08.29.10.12.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:12:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.243 as permitted sender) client-ip=95.215.58.243;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 09/15] stackdepot: store next pool pointer in new_pool
Date: Tue, 29 Aug 2023 19:11:19 +0200
Message-Id: <f612aaa765d653e0f2c64fdb39adb1190b10a762.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tY6t+d+v;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.243 as
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

From: Andrey Konovalov <andreyknvl@google.com>

Instead of using the last pointer in stack_pools for storing the pointer
to a new pool (which does not yet store any stack records), use a new
new_pool variable.

This a purely code readability change: it seems more logical to store
the pointer to a pool with a special meaning in a dedicated variable.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 11934ea3b1c2..5982ea79939d 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -86,6 +86,8 @@ static unsigned int stack_hash_mask;
 
 /* Array of memory regions that store stack traces. */
 static void *stack_pools[DEPOT_MAX_POOLS];
+/* Newly allocated pool that is not yet added to stack_pools. */
+static void *new_pool;
 /* Currently used pool in stack_pools. */
 static int pool_index;
 /* Offset to the unused space in the currently used pool. */
@@ -236,7 +238,7 @@ static void depot_keep_new_pool(void **prealloc)
 	 * as long as we do not exceed the maximum number of pools.
 	 */
 	if (pool_index + 1 < DEPOT_MAX_POOLS) {
-		stack_pools[pool_index + 1] = *prealloc;
+		new_pool = *prealloc;
 		*prealloc = NULL;
 	}
 
@@ -266,6 +268,8 @@ static bool depot_update_pools(size_t required_size, void **prealloc)
 		 * stack_depot_fetch.
 		 */
 		WRITE_ONCE(pool_index, pool_index + 1);
+		stack_pools[pool_index] = new_pool;
+		new_pool = NULL;
 		pool_offset = 0;
 
 		/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f612aaa765d653e0f2c64fdb39adb1190b10a762.1693328501.git.andreyknvl%40google.com.
