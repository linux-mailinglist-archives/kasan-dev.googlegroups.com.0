Return-Path: <kasan-dev+bncBAABB56ATKGQMGQEB4KI3HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F73D4640F1
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:06:48 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id i6-20020a0565123e0600b00417d29eede4sf4173900lfv.12
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:06:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310007; cv=pass;
        d=google.com; s=arc-20160816;
        b=KEl05SuhOPJDABOD0mnSALg6x8qc2j3jGP3lJgC83KOoYDk7NXsyV1iEeuHwOk9Opy
         erdtK6VVv07uKvdXfleAeh7pYozSpVqG+0GQ0zrNMQzuks+eNwB3DsUB/Zy4wqt4sxf8
         y9HRsWcR9Y0QCVLFRzjB205K55lFyAvCTToUfxzyxsLfogf2dxCnvgnJiCJe5oPVrOJB
         n9rCEB2+cthxABKhJnScMANQb1HrBEnV8q1kOGlBnAEDzD7KSdgaOz/DshcUiwX3mfXl
         4vGh7oYF3fyhRQb8L54O2bYmxDg9G1YjUXxs1SW1142ygZGKIsHrPM997Agt9c5z6/rG
         kReA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hRrKCb0BqH43RtcdoxjQUvpeyWS26cTy+xKOC+YZL70=;
        b=KitLQyZBc3pZxRRqPZEoRb4MsbUOhIKTxQPMxMl0oTZZ+ZqYqEi5usiJb20oNgAUDy
         yYPzYCVtQv08GjRvVCbAHAyRi9l449cxlirI/3ertg+7ZSOp6HqOBMe9qufD7Ppy8NfL
         cuKWY230ZDTKujC8x05R+TVc5XBUy9VEyNKUCrEfT0sQxIYMkOC2yqcowkLpfA8e/hls
         GAGqpykrLlAVC692xnU3o3Kvp7KGhdvoqAQmkG2IwSd7O1qNdzmNLOimFu9rANGm5VCZ
         EOSwI+h8oab+gFeug0UcNzareC4gfgYnkDzyLOmmK7tGUeaZDQ4zqFV9es8SJYUlrGll
         uSnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NQfqmix4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hRrKCb0BqH43RtcdoxjQUvpeyWS26cTy+xKOC+YZL70=;
        b=lo2jY/3rWSGv6ULIz/tk6AxQnEIXv8DpWTc1VZcSYm0UYM2MaDUVObJoIiMOVLv1px
         LKyNQ1hczcDu7ty6BHhKxdN5/qN+k6TTQzoATDs7J2C+8A1m0uo4HTvBNm+cI4EDi1/f
         vDGqlAKTZVMGgYbqFG3VnbAnPsL2F7IZamqMF78BoTRZUhbtCfRf6YHImenRIUKG4+Gd
         7xaGpwP3RiwovKo6rIldzsfSA5UonG56T3qNeHX+xqIw76zqv2ICwyznwn21vsdVZ6/O
         SnQZQiUfzjKOajO4bwN281Hoacg2vQsxSEhBjbZLCytGX3N1ATTvN79vG2gJLS/SdJmt
         ZfQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hRrKCb0BqH43RtcdoxjQUvpeyWS26cTy+xKOC+YZL70=;
        b=1cigJ+8nG4KaiFe8IwJCBwRk7sAEFUYL11r3s0uIWU1csNIwMCyVyJyOBwg+CDF0VX
         316undpNBM8AlNhJtA1m+WeBKFXYHR+zPkOzzcAR+opZUEMfFYMscKUUu1XaOaHSK5X0
         4GUW84AdzZXN2F7mCYmzTJMxS45AowBRSkEn+fE0YEKNfdmBWHD7QeuSqzY+Ya1+lHXZ
         epMaAMLZhrBKWbfUT1Ev20nt9MBuEDfg+cgU8Q3Am0OYipVYIM6g+x1iiRbSpncDUa3O
         7KVmhlK/Or8GRKTVy7aV569Ghi33Unq3IlE+EmNC7CcnoytA/SPzSkhd3JwaDjCIAiKe
         G4KA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uyxOTIBnEcgCkH3EWjIxyqRiUgGnmNXdRPYxn3I38J9iIhNcb
	GtEHnHMWW1vHXG+jVDnYFDE=
X-Google-Smtp-Source: ABdhPJxHpR7Wq1flYGME4YstPmpWSoBrMp2tL1wqBAN0yIYkuDTHDjGcfCdS7tLg6qydXm5opw8Fqw==
X-Received: by 2002:a2e:86cb:: with SMTP id n11mr1591629ljj.425.1638310007736;
        Tue, 30 Nov 2021 14:06:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls95214lfv.1.gmail; Tue, 30
 Nov 2021 14:06:46 -0800 (PST)
X-Received: by 2002:a05:6512:3212:: with SMTP id d18mr1874832lfe.285.1638310006767;
        Tue, 30 Nov 2021 14:06:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310006; cv=none;
        d=google.com; s=arc-20160816;
        b=gFVUtoABVICis/jyJovi0U8kTPjc0m/Ma7xplj6CySQ6BXSnEy3Wknmgz0uYTPY1m7
         auvh72oFZWbcDwhjOAn4miMHqH35Pw6fp0hWseNXkicfLJymfgJ+vLx62ieYp4rt56Ll
         7iTDKNcffdjXgEWrHeq0q9JOgoOlym0hDOKuA1NUcyxra1n9DHPrikCID3dNRTnUXnn1
         G5cb6ZGgmd6AprbcZC5DeL9NKfRGGbwtNa0OQqpDBXjzUfq663c9VYOqpaua4jTXQdqc
         BXMXAFLLaUv3P8Gu42q/KUvH9+oBbJn528+hEByoKBK3FGDeOsWjRqxoXRBi8QMaIv+O
         HERw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XbhL8TrmzwL9tq/+XeKdOp7BHc1RVFQ8fUYh+mFdIuI=;
        b=jNck5EtmTebFF5AHSSIXlcAbe4Zpgt+IYlTJsMzeou5ObNsHP4b1JmHuQqfFwH0q9V
         xMie/MPoplKTOQSgAgLdN7HPL7ZkSzNWQTCDGes+c4W8/iLwRwz09xCBMBz+veCk36+u
         ooIojF9H3iYVBS3SzgGYC16eHfmSS1khnrJKxpUqmBDLvdyI8oJSCFVwD2nooVhI7jgJ
         coCFdxuGLfyGmzk3DwYUcwqWa7xoAN7M+wnIm9oSk1kM6pjbX4JBTgqj+rpQ6Ev4bgZ9
         wtKvh1iPlfx9SSAbhVTtTXe3tA8Bt9ATD3e+j2NX8bJPacvoHusUjfzCoEnf1rDWN+47
         gJ8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NQfqmix4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id i12si1936465lfr.7.2021.11.30.14.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:06:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 15/31] kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
Date: Tue, 30 Nov 2021 23:06:44 +0100
Message-Id: <0cfa94ae26c59bba4329dd384b5a8a5bd6adb891.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NQfqmix4;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

In preparation for adding vmalloc support to SW_TAGS KASAN,
provide a KASAN_VMALLOC_INVALID definition for it.

HW_TAGS KASAN won't be using this value, as it falls back onto
page_alloc for poisoning freed vmalloc() memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a50450160638..0827d74d0d87 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -71,18 +71,19 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
 #define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
 #define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
+#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 #else
 #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
 #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
 #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
+#define KASAN_VMALLOC_INVALID   KASAN_TAG_INVALID /* only for SW_TAGS */
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
 
 #define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
-#define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 
 /*
  * Stack redzone shadow values
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0cfa94ae26c59bba4329dd384b5a8a5bd6adb891.1638308023.git.andreyknvl%40google.com.
