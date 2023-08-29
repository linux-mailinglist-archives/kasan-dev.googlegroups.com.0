Return-Path: <kasan-dev+bncBAABBSOOXCTQMGQEAEK75WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C37D578CA71
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:13:46 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-4fe565bca92sf5216198e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:13:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329226; cv=pass;
        d=google.com; s=arc-20160816;
        b=rSvQ62ELiLYWrvK8AJYZ2sMIO8ME4Bm/oQtDC5qfpi5fNxftsGxcsu76px8DeaGWB6
         kwmufOj2nIsn9g1HXPo5oY5gC21jNnbtCEWOdYbAfYx2TmHoTPRabAIOFiOP/p1aZ4uU
         Q6PshaSH7SNEQhTh4KJw3y0l1fcIrfSPr/qovEVhoiMreruqOd/0Q0KjDrB8VY/NfNze
         JJes8coC0JAvqokhXykP7uecu08iu3Na8C8w42ZUSYYeay0FDfu1FQ7ffOVEbq/KrPKC
         g0sczPKCdh76IihzU9tjqtgW1b0e+2ySab090TETmtJ8lJ3LbrD732y5TpdqrJjMdJIe
         MTZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gvwRYXaOnwwkQUGqJn5Ly38tQl8/Uk/iSTgnz9JXFHM=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=z/0RliZiT79Ba79ej66hMg11bTc1AeB5SdeN6YqbTCCt04ya1LZjlSj7UbX2QoTQ4H
         fnwjQMqsLuJW5zuPBQbF2Pz5viI49mKnIRTP+S8DjVv3OyjQ3BIVwZL0EDtrqd+mpAds
         xVQ0GLAzN17YFhQPUptx7tnqUfE0p8K/iYbCAoADUH/MWR6HCdyLXLfs2Bp0UCnI7saI
         ePOZ/ugVxnMos4l4OTaC0iTehdU+9UTGwPKf/AJr+xfmoPUGlR1hAbwYBfTno8rHgrJp
         Q+XlPl3omlO9kAdy+YjkzpL/YmRgZ12tLYngix7QFM5QGg3S6sa6Qed8tAtkWMqQTqBR
         rHwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h6llS9CH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.244 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329226; x=1693934026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gvwRYXaOnwwkQUGqJn5Ly38tQl8/Uk/iSTgnz9JXFHM=;
        b=bNsmEpgkMJ+ob9S/hBtglpw1vK3ubA384X5KuoIrouAs9Q+m2T9WMx/T06Lbh3zKKd
         IiLbk7kyCgGWO5MpTai6x51C/w+9OQMWDPv6qhTrqF3dRU0N1B7MHi9XGady8mRRiyE1
         uoLKAQ638v1mPd/pvGa7z4izYIg8M+nFllUzsn58okrkRgD+6t5zvg4uz0AO6lw+ftlW
         NdL8Q3QGAf8lDqU6SiqwGUZ1ojh/WcpLJ8hEKUjjzYpES89RPypx4Fz9ruCATsFfKUs/
         nRJCSuslrqYVz5GDsd3kqVmL9Pv6CnNSLn0NnK1EoK4HEimrbnexSYzs1ZThqBbS2awD
         sCYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329226; x=1693934026;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gvwRYXaOnwwkQUGqJn5Ly38tQl8/Uk/iSTgnz9JXFHM=;
        b=VgVkrNv6q1OhtDLz1jJXzRjupBOuwlKPgybkpv7cqmzYhkmavhpn9zjx9I7M8RbfOX
         uCWV/EVZXTEP30Q3wkppNA7HnUal8Yugp2QHN01SPvMrF/5dAcso17K2UU8HwjCqjn5/
         +wfjgZHG8JOQx3gZW/wecasfz1cZ+Y44gKbra3nW03VeZLpx2PQ8xABffEaKlGhQChaw
         +J5n+g2dp2WJiyxRqMTx4OgizH5D3aXK9VjxHGyWWkeTGd9ZnO7ATp1N4Ry+PSJxaE94
         r3tA+OMYXzl6FwUr870ao5pI0cHl7DT7uIP8ln4ZQKMj9gQ2xxDV26gL2Oh108dykIs4
         KTpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz6EuhaQ4mtPpCpQBv2smRxB8BQ9KJEEQTicDkKQrqubBHGa4ZF
	fO5RSpoZtNB4ftVhuuvnFQk=
X-Google-Smtp-Source: AGHT+IFW+aUjVfqC3iYPoHEBsoavN1Ja5yevELV4PlPLR6ZglItrOLgaD8v866bzyqN5Kmaotys4Yw==
X-Received: by 2002:a05:6512:3b28:b0:4fe:ecd:4959 with SMTP id f40-20020a0565123b2800b004fe0ecd4959mr27107186lfv.32.1693329225605;
        Tue, 29 Aug 2023 10:13:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4f08:0:b0:4f9:5599:26a with SMTP id d8-20020a194f08000000b004f95599026als166781lfb.2.-pod-prod-08-eu;
 Tue, 29 Aug 2023 10:13:44 -0700 (PDT)
X-Received: by 2002:ac2:4e0c:0:b0:500:7f71:e46b with SMTP id e12-20020ac24e0c000000b005007f71e46bmr23359057lfr.1.1693329224145;
        Tue, 29 Aug 2023 10:13:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329224; cv=none;
        d=google.com; s=arc-20160816;
        b=lLtjhREOlGH0cYbb7tZyg0Co8JBHqev9XMdFci82J4X55yaAaKMt03oSDXy8Rct7Zk
         pwR//lb909ER9O7f2asRmBgkRSKlFdOCv/ZI46xuciU+RvrrP42MhA/Rna2Dl6Ou4yx8
         9P0l+itYJ2LsZ/jCafQtO5OQuNuR5syKrUReHPCO5HUQxPBZNGc+PWdHZ5rLfBF5YX56
         Q8JbTEG2RyCB1U7gy8frq9vWZAEGWe5DtifLvkiBp2jmzAgugVlQrop+q51qPUD68Dul
         rIP6GbRVR99SBPvNo2rn4wbWqmewAQP1wY8HMf9t5NCoTOHwiDrYBEWQssS+U/NDOpsE
         w8pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SXcX5gR3dSvkxNFtne9AIJ3MreGstDXokl9zt3D1S94=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=i43jokgmB+6gjx4g+2JM6ANiMAVbu5Fw4xpp93fZkFBHBT1n15DgRAYkIvR/JZ/BI+
         6ebWFcvHW1rhGrLEtzQfNASMgEUaqcvkN2EEVBS2sTRA2s684rEPyvX626Lky4uXGsfy
         EpQS/GBrbQJK3mabspjrpmx/sE639Hx0K6JFV0SXRLOKx8e4FnuLYsN9NqsBdeURNckm
         mnfXPOmEhcHVfJCtVdkTjHcHvk6j57m7kt18XJY7zikkZDnBbf34qmdKda62OmwjSWYr
         CTMp4ZKrAUHPWb8ry9SmBLgZbRLrm+JdHFiW97dLc16WvH+m17B9XxlsNFfKFU2kxQHI
         k1NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h6llS9CH;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.244 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-244.mta1.migadu.com (out-244.mta1.migadu.com. [95.215.58.244])
        by gmr-mx.google.com with ESMTPS id a13-20020a056512200d00b004f8621b17fasi679735lfb.3.2023.08.29.10.13.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:13:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.244 as permitted sender) client-ip=95.215.58.244;
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
Subject: [PATCH 12/15] stackdepot: add refcount for records
Date: Tue, 29 Aug 2023 19:11:22 +0200
Message-Id: <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=h6llS9CH;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.244 as
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

Add a reference counter for how many times a stack records has been added
to stack depot.

Do no yet decrement the refcount, this is implemented in one of the
following patches.

This is preparatory patch for implementing the eviction of stack records
from the stack depot.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 5ad454367379..a84c0debbb9e 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -22,6 +22,7 @@
 #include <linux/mutex.h>
 #include <linux/percpu.h>
 #include <linux/printk.h>
+#include <linux/refcount.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
 #include <linux/stacktrace.h>
@@ -60,6 +61,7 @@ struct stack_record {
 	u32 hash;			/* Hash in hash table */
 	u32 size;			/* Number of stored frames */
 	union handle_parts handle;
+	refcount_t count;
 	unsigned long entries[DEPOT_STACK_MAX_FRAMES];	/* Frames */
 };
 
@@ -348,6 +350,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->hash = hash;
 	stack->size = size;
 	/* stack->handle is already filled in by depot_init_pool. */
+	refcount_set(&stack->count, 1);
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 
 	/*
@@ -452,6 +455,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	/* Fast path: look the stack trace up without full locking. */
 	found = find_stack(*bucket, entries, nr_entries, hash);
 	if (found) {
+		refcount_inc(&found->count);
 		read_unlock_irqrestore(&pool_rwlock, flags);
 		goto exit;
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl%40google.com.
