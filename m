Return-Path: <kasan-dev+bncBAABBHWBTKGQMGQECXH2AMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 679694640FE
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:07:27 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id v10-20020aa7d9ca000000b003e7bed57968sf18164770eds.23
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:07:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310047; cv=pass;
        d=google.com; s=arc-20160816;
        b=OklOvBP3ypL6G9JmdfsXrYHWvPZrXyPmIlHvcS6vHBQnhY+9wTEskvz5+6EzAWScMp
         Sn7WTaHJFoE0WhkMew3DcRigQ3iwrc6hYnjJrGQ5ywUFVkNhvx5qycmh2swUtvTnoO+f
         OQE0jMcrRyRLj1qDA+AH2NPlC2SadQ6V3Glujv/nWPW7znk8QA8OyZ2x0yQ7ubaAU67I
         jOOB8DI9PeKgaUOYfT0mc4kw9IT3RUtSXzEgL9L4EWXVkaVeJb+snv9TNIMrW49AI9DM
         Q4ltopKSqRLgcQ3H2bo6Xy9a3m1AtofhJU5ow0Czvty3PMrS8+Rbj5Bre0C0FYiAeHIt
         Z5ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6dvitYdYtuZFnuqM2yHc+FS/1nCmTbR7EJpeoosJ0Y8=;
        b=KNdCDEwUlm1dcckZhlNVA7w06yDQGXi3c7+Yp7iyMH+XvPnOcugBsxySu/9DhKL96b
         zQKLeg8kdkfWZyaot8xCUqS3Fgry3b6t/LzYjfiLzdDSjR8S/Q6xLOXZ34hwRGjL3web
         K9NaHT6UZigW9vkMYvhlDRZj98TM7m+a/za5qGJ2w21GtSp8TDAPPQj51PxTyk7KyM9R
         5o+a8UePKoIEdZzP2yN4rk3S94h9pe3uZBXsuhHfxtIEi0TUy8EQfedrxXMlfaPaPrfK
         j9XtKWqLjnz2zCmGZMLctjqvhhzH+wX8l19gxVcYqTh1SsX0vYl7vsN/BrMPvtUQM6ll
         ARhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MCS0gr3N;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6dvitYdYtuZFnuqM2yHc+FS/1nCmTbR7EJpeoosJ0Y8=;
        b=p3aPpeXCbEuTYZzdO2u8yIK5W9GV/ny44GCqZZWq0C4U/pYngmi1mBYf01Dr1Qf60q
         xEuEdEjSQd9WszXjAWWj+pKPmkdnuOGbblCIEBz87Ub6YKEHyOuqerHldbfStSYQw7Z1
         Wl9BbcCrXX9ExW2Gh67g2nlrOhbSiGGK8hBBaqiG2DLtavZydLa8xAbb9gvjJELavnaI
         B+UxWu+exsWMxeYb4S/3CZotzpKHLuWzkLEDfglXYxL6F3NIqoDoPI4wCneD2eTDZxEu
         F/rZKoWAw1xC415q7sWn0fOUttyRsltLonaC+js2Do7JK0iS3z4s8Znp/rC5D/ftpQde
         a7rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6dvitYdYtuZFnuqM2yHc+FS/1nCmTbR7EJpeoosJ0Y8=;
        b=AIYqBb9BOHEJe42dKin9MHnw48We5uUidgSakZOT0V5oQ4K2dvAV4jCSytV4sC2+0h
         XVA9AqasuyUerJho51MejQoGnxT3fkhnKSHEJkvmGdXJ6rkpueoc8iPb1nHDBeDFLPve
         loQJstO21fZ3ZZNxAOx+94apFvwBPj0AybpAUlIqWeF4T0jKpDtRQ7sXG94eET53hpo1
         TewJANlJ7bvSkGfDgVO2O/yhfmrW6Io5VpN1PORPzlJleYuDc33HUTVww2eiEufLwRcK
         hnF/9MM736Nv85csiIlnTMDahrGCL0dtgpTon8XaY4dugyKkQTe8xl8CpbvAPx8Qs/ir
         icXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329G20/WytB2VoIRtwKV1WdnNESn4XflPKSgn4J9rvXBwtOb5Dx
	vet/2IZI92lo7wrI7hrpr9U=
X-Google-Smtp-Source: ABdhPJxgBYIoSLd1OmNw3jMsdTPwoeaIQbd/Gjm5jtyYho0mDSRDh923kdCquE8dyFUMR5b37P+xBw==
X-Received: by 2002:a05:6402:604:: with SMTP id n4mr2545722edv.226.1638310047113;
        Tue, 30 Nov 2021 14:07:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c517:: with SMTP id o23ls248066edq.2.gmail; Tue, 30 Nov
 2021 14:07:26 -0800 (PST)
X-Received: by 2002:a05:6402:42d5:: with SMTP id i21mr2463232edc.373.1638310046515;
        Tue, 30 Nov 2021 14:07:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310046; cv=none;
        d=google.com; s=arc-20160816;
        b=lMlICL0UVs5gCD2QmCRU4bX9mWENMMDE+aFnBYHsiOdFGMcAO4eqF1KLQfMYZ5jvTe
         mH5MuSV4+7ZBTi8MOVPcxb+LT3ztQWZ4Ogm4piGaewsL04oqQYIOWqya5X4SriPEL55E
         f5kQCWdjjJzOIZRfByS/bDeNEzaHeuyUqMrbP7bOGXaQmmjQpsDwKVfVqxL3GG9E/Ag5
         1flz65N2d7XQGhm3IURDbnPatF6dJsc4geRvazvuXYTjZm3LNfEQPwvjBAjLawFXi8nS
         BppraZOKDtRf/6QdX7r2d8hH5hzEk3exvQZoloGhZH0Q8ABgsSmwpLplpmkpoT/h6zLT
         8HwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nHVI23+3UF63ZVUN3WDdsPua2nJbVrQ0CU8a80/ebmM=;
        b=PNU3mZ4xYsGu3Rf56EEXUv7HR9ukeCdCKMHxCq+pCk67oP1yd+4deH4z6BUymXI2e2
         CaYlPlfF50KhzQkGIgOxR/omyLP6SdCOCshq8hFCaC/TAmDZf3tivnBq1wkR+lcJQxut
         /uJomaK4tFAnxbQgOXqXg9tCBJlQnoc1VJN6g+CUPancjpXnBFCQsk6RwcIpFslmxOze
         hdNi5t0B2LT1HNIBCyHCGDa2Q8CxLgCdL20lXtR80FEkhsmWZSsLV91zypmxvFBAR27F
         /c+S7RUKQ+hwMCA/c43sVOb2O7LRFjdcxz9b+AdT8Z5KrlmIzc2mSAOwpqftqMr92vlI
         g+/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MCS0gr3N;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id s8si1102018edx.4.2021.11.30.14.07.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:07:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH 21/31] kasan, fork: don't tag stacks allocated with vmalloc
Date: Tue, 30 Nov 2021 23:07:06 +0100
Message-Id: <4fbc6668845e699bf708aee5c11ad9fd012d4dcd.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=MCS0gr3N;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Once tag-based KASAN modes start tagging vmalloc() allocations,
kernel stacks will start getting tagged if CONFIG_VMAP_STACK is enabled.

Reset the tag of kernel stack pointers after allocation.

For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
instrumentation can't handle the sp register being tagged.

For HW_TAGS KASAN, there's no instrumentation-related issues. However,
the impact of having a tagged SP pointer needs to be properly evaluated,
so keep it non-tagged for now.

Note, that the memory for the stack allocation still gets tagged to
catch vmalloc-into-stack out-of-bounds accesses.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 kernel/fork.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/fork.c b/kernel/fork.c
index 3244cc56b697..062d1484ef42 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -253,6 +253,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 	 * so cache the vm_struct.
 	 */
 	if (stack) {
+		stack = kasan_reset_tag(stack);
 		tsk->stack_vm_area = find_vm_area(stack);
 		tsk->stack = stack;
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4fbc6668845e699bf708aee5c11ad9fd012d4dcd.1638308023.git.andreyknvl%40google.com.
