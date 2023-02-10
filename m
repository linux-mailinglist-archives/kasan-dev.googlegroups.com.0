Return-Path: <kasan-dev+bncBAABBXPITKPQMGQEHJUCD5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 2949F692910
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:17:18 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id g19-20020a056402115300b004a26cc7f6cbsf4300294edw.4
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:17:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063838; cv=pass;
        d=google.com; s=arc-20160816;
        b=vc3KcQcR4c7r6DLsTBoYbCY1jIehFlz158Evf6yuC32dgmHAYp+EsEyxoYe+GkVO/N
         jGQ691SiK33B0kr2ABDCpyaqmMl11fR6zFP7rd87G12qfqwoqw7RePIWCoB7Ry2Qc9wo
         F0E2EWMMa1mtuyj4NKdGig9tXScb3iODKfBF2h8wAt9EW//q6+6Xhy8YDE+VnRWmLj45
         qOJeJGwE/avzldDIv9LVwAYkivomRIMiA/jeCnxMI1UMHd6yUxQcpYtzvI9ki7rVT0Bw
         Xf7pW6mBzOtTjrIPWEFY46h7kZYvFiI4UOLgISwyAuAw6hRgVTzW1dnBEO8b5UCDxM+W
         zaJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LHlnvbv6wY2BFgY0BuAfx9YAjuVGN7uV+ui3aZfumiw=;
        b=o9vjr38t8QqODxKAUqvCrRnyD7lDvB0gin3f3VWpJepUayyQboSE+qyY9zdNZmd5BR
         yiCuAYnepKebrShmeGiplL6+ZdZy6YGBGdYXKbpjEftEm78R57ltytBK7J3A3XAcK0sU
         V0Uz2mshSMgMQxL5Ym/MWlQSWAv18OeTdZFLm2yOUkWjV/MBIsPbndgjDXy1YBS4OtJm
         7Un2AbYvwQV7UqgiFyG2+GEeDJ1ezlLlo5iULeHwW0hllvNRSgLmJioOPfGSXxJwA0Wb
         lbgpvcdjs6AvYrDIGBvchGtoauCnWmJ+tcJ8ErXvdZL0wg4Xi/FPCb26dLHk7Vmo9+Gf
         onUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KLl8qvzo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.89 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LHlnvbv6wY2BFgY0BuAfx9YAjuVGN7uV+ui3aZfumiw=;
        b=tLYrONyoX9MqLuhQGEUp/i/EJiGw3/sFwAjkYkgXY3CcK+mxc6v5JvVM6/qIp3tOlc
         7UGCn83oMsCXuO6lXY0jn/02iEDLs0wHEO3Ng1Vt3jLGBZJhAoDbNKv7RfmBpwOI1B/9
         N5gXEy35Wlf2GvtUFEVhGbpYMlYumMn5RmJS3Zcb9FktuTGwqJL2Eb0EwWyRbvOiEMnX
         lXTburu8CZ9nn4uiR71pQDbj0t5vKlI3aMMJzb/JD12UhBTexYGUlD1yyYBe/Km/NmSo
         rL6dMkaFUGfcB1yjBISw1EcOIKcMBri/ivFbjEs2JQZTUa6ElVRPjC6g8DiyJH+RKjwf
         yD3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LHlnvbv6wY2BFgY0BuAfx9YAjuVGN7uV+ui3aZfumiw=;
        b=pa+kGi9sAKiuu2FUqzMRRiLMoEqeC8Vf8WPUUv7a9TQ3MfTM+AzHzii9ywJ+3dw1qX
         ZUPF7y1GKYg+Zog7AmieSeS8X8IXui3xiBmYIeI1OtOnzSNgy7viw3E4Cc/IWMk1tlD7
         B4UfXt/jnq46CPe49JXJapn8XfWmKj4NhdUM11BQv+H//cBA7/CB/nkKryxPFJCA9E5y
         M3NyWvb+iGPPQHHXNQYk3lrbh3M0zB0USfQ5zQd/YrXOrI/TriI7t9ncpKU+jjyHnfOK
         oDLLdidJwjPZdrSeHlexhG8XJzmNi/5hSXuETjA2W9jcf4tfh24+SUFxR1XV9jsWJcrL
         vHjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVn3TNvjUf4/Ar20Zns/KrYDGGyVU/qSqMNNHms2ZA82of3H8Jt
	OFyyRcUsFCddbceLnjjAGJI=
X-Google-Smtp-Source: AK7set8rEHYKkjb4Y585BjG9WSBLIGrCUX31KTXjGkOn8dhXxhS854kIh2woEsAcnbEIWqD9o92oxg==
X-Received: by 2002:a50:d0c3:0:b0:49c:b721:142c with SMTP id g3-20020a50d0c3000000b0049cb721142cmr2887285edf.1.1676063837886;
        Fri, 10 Feb 2023 13:17:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:52d9:b0:869:2189:ba11 with SMTP id
 w25-20020a17090652d900b008692189ba11ls4611974ejn.9.-pod-prod-gmail; Fri, 10
 Feb 2023 13:17:17 -0800 (PST)
X-Received: by 2002:a17:906:e213:b0:878:71fe:2f12 with SMTP id gf19-20020a170906e21300b0087871fe2f12mr16089128ejb.50.1676063836936;
        Fri, 10 Feb 2023 13:17:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063836; cv=none;
        d=google.com; s=arc-20160816;
        b=ShtrYSWrZvQ/osDjHRPjVjBZDyF+NjPFR8pvQUlmTnruHhSuOZ4cgDgVyM6HTxtVP6
         CmSjLLkVFvgE4AHIQbG1Qu2tGVFzayu4bEOA79whWx0H6PEDjwrpugfj4Vvd450T/YyU
         hE/jWKiXjmgw4tGtTGnNfKkqaHVFirbTIZqLqmnhbI2I9EwB54l3Qnskp/If/MgsbNsg
         62sqQb0X4UDQvuWQE7nj0+ADgLwRCAi8kQqaPxBJ0ckp8V6Hk5zWlIOM2HwjOWucxuAa
         AXTfVjQgNIedaOcJxe35hOW9FHdXFYqxUP4oEQZA2u+Qtr6gNyb7rqcamays2TJBahEt
         5v6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vdN0qpq7PVidlsBHChLWKkpFVAJ9uzHha5rImS4k+3M=;
        b=Htn9vxeEMkuhRYgiCD02SJt0iMWurh8wXheFku8LtBCBvnR2TvSNBGlrXaC+H6+XJJ
         oy+u+cIozJhJu0tPb1Y9+CUnhhuQCUOaOvnZhPdHE14pLuaPJeDrvwtPe6kPhDJYlRfh
         fL5VGwuIDzcl2T9RjiGNHmrVtbHBdtn28Mzu3pnOIy93r5lv3hSVQUyJ37ENe7+9AoGG
         VaIkTmHgXfdjyGjorG7Rh0aEfUnA4L+hJt+oDWHGHP+Pjh5cWzc1LugQwD9IJQGiCErp
         PMDdpefnWRHoo/CJGhEpoSwW7agyR+LnIZvacQyOkTS4CO7gw1lxVJ79pIcFg8jgj7m4
         7q2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KLl8qvzo;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.89 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-89.mta1.migadu.com (out-89.mta1.migadu.com. [95.215.58.89])
        by gmr-mx.google.com with ESMTPS id i19-20020a170906251300b0087873f29192si284541ejb.2.2023.02.10.13.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:17:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.89 as permitted sender) client-ip=95.215.58.89;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 11/18] lib/stackdepot: rename init_stack_pool
Date: Fri, 10 Feb 2023 22:15:59 +0100
Message-Id: <23106a3e291d8df0aba33c0e2fe86dc596286479.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KLl8qvzo;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.89 as
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

Rename init_stack_pool to depot_init_pool to align the name with
depot_alloc_stack.

No functional changes.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 97bba462ee13..7f5f08bb6c3a 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -218,7 +218,7 @@ int stack_depot_init(void)
 }
 EXPORT_SYMBOL_GPL(stack_depot_init);
 
-static bool init_stack_pool(void **prealloc)
+static bool depot_init_pool(void **prealloc)
 {
 	if (!*prealloc)
 		return false;
@@ -265,12 +265,12 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 		/*
 		 * smp_store_release() here pairs with smp_load_acquire() from
 		 * |next_pool_inited| in stack_depot_save() and
-		 * init_stack_pool().
+		 * depot_init_pool().
 		 */
 		if (pool_index + 1 < DEPOT_MAX_POOLS)
 			smp_store_release(&next_pool_inited, 0);
 	}
-	init_stack_pool(prealloc);
+	depot_init_pool(prealloc);
 	if (stack_pools[pool_index] == NULL)
 		return NULL;
 
@@ -399,7 +399,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 * lock.
 	 *
 	 * The smp_load_acquire() here pairs with smp_store_release() to
-	 * |next_pool_inited| in depot_alloc_stack() and init_stack_pool().
+	 * |next_pool_inited| in depot_alloc_stack() and depot_init_pool().
 	 */
 	if (unlikely(can_alloc && !smp_load_acquire(&next_pool_inited))) {
 		/*
@@ -435,7 +435,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 		 * We didn't need to store this stack trace, but let's keep
 		 * the preallocated memory for the future.
 		 */
-		WARN_ON(!init_stack_pool(&prealloc));
+		WARN_ON(!depot_init_pool(&prealloc));
 	}
 
 	raw_spin_unlock_irqrestore(&pool_lock, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/23106a3e291d8df0aba33c0e2fe86dc596286479.1676063693.git.andreyknvl%40google.com.
