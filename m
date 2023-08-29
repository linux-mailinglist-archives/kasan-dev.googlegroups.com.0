Return-Path: <kasan-dev+bncBAABBS6NXCTQMGQE2YIECNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 61B6478CA54
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 19:11:40 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-50091545239sf5112096e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Aug 2023 10:11:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693329100; cv=pass;
        d=google.com; s=arc-20160816;
        b=xoQJWAKt7xqVqkIH4krwHIYrJoLQrXywMT4G76Gkj/lG0+hHyhoDWgwCs1T+175d3Z
         PSKf07c7IW7EzTAivdkXj+vcGQ4fQc8aUBWjt2VEs3LhbiOTBvzGUjosXBCtEq8IyjiG
         V0KuqKChDywjwRnbDmSbnSEEzNvRCxkRlEkIt1lTWrTsIW7PFGuylKY7TO1VzSXODr+U
         4EsyMYC65nDNNG7ZcneXgCou1HARzsTD9cvRb0pub2AHvcJxduNFoDqZ/v9TY4EANLex
         VLTkNCSX8Pztr5MJFCsqoIQPVWymZcmLpF2I/vNV4A8m5Urw8n/e+218HM63TdKFQF9Z
         pP9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vFlEAYgDyI+ZI8tzC0vP/msLxqZNujGcjSQRgEsu+qo=;
        fh=ZTTSst3850TI+4y2eqKpcuCmJhEtn1qZX9lpGyHR9Jg=;
        b=JXTzv3D47iRQ3ynk2IzSHKm2AmoRU6bz6oFeYoP2QgWm8NAPPBPcskH/F5yLcnjjOL
         9iPseUUozNpPo3i5v9rhwFiBxg88fBJfGWcASKNjaMKmDIOlpI4UMg/D1Y9APACCg1m9
         aiZNKN7HZXkaBCIjDtao3T3EwX3wl3ohPCHaaKE5UjN67d2rVRZ00PURRJtrlxZjj11Y
         Lxv+diInmboCPBXcOrWzI739UT7Rs1pGstbOQu46iqgVf93HdDF7AoJLFtBMQs1WPLO9
         wlen3vRPQH/z2XzEQvKeruAlcfptRgrnhLTDDnuzU+MS3wowXe9U0awBe5kEozMMob+B
         XiLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FdmqrQoR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.248 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1693329100; x=1693933900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vFlEAYgDyI+ZI8tzC0vP/msLxqZNujGcjSQRgEsu+qo=;
        b=NqRB+Z4HKfFtevpagMJYvFCBtupANw2KWRyrr/bsi4TiUTpq7SCPjDi8C6yKzPQBhO
         XuW6+FICiKhZVMZsDz3hAJINnt44BKFTbbEV36mAuCvd0DGQAuB/PBs4ttUgXehpp8L+
         rwTIjhEDQgACdopDWgoMlQHilt5IlGXnsPw7miOmzQimNxGM6dBPYZOCbjl0yafLCYjP
         tjKYROXb0wtNEEPgMA8WQAow0e4YhnugZIX0hgL+2ZCdHjzpatjgFxWDWOwGm06bIDGX
         ipp197pI1xqyJxAhRWEIhyOw4U0UEBpPSkpuqqWhVjAUlUWSMdyQeVW6IRhYgAn/Fy3G
         NaoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693329100; x=1693933900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vFlEAYgDyI+ZI8tzC0vP/msLxqZNujGcjSQRgEsu+qo=;
        b=Ht9gvcqw9+BJXe92zc4Pjd+nIiQNgqlp592oxWN/EKCCpQnkf333xpzSDMCbNe7bmO
         dXmhcZCMsH8Z9PiMxlRkmyckDXL7pJXZEAnifk5fe73oy+ZvLY9PjHfCXSp7CztjQf0w
         uX0uG8HVCVxXqSw6w2JLQYbMa3msPGSuSw4xk5XrdGIVURN69TYJdhXJiAZamOc9e0rj
         cJ9TIJqjSpOb2kkgUWxtaaLjBdl/2lk0WCysY4WA2dvm8ld5rZXfRJwhK9cW7HIYBLBA
         VB1/VDpqSlCTqN/dw9mT0yKG/HoL0/s5Prlz89zbSRcSLsO/ba9oQBIQnOJhzWwycBOV
         21xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyG/ScxSEkAIVNtwxpCWj3FSlJvDQzm/F9suSfIMwDmJvEJiItm
	OMXl/HH/gpR23dqTJ9rnZVQ=
X-Google-Smtp-Source: AGHT+IEnA7kxE5YTdBJ3Ym6k7vYnzgp/cXDzXavOYAfHxPUJoyjWfcu8LX5LysDwVb1ViC+IjBbdkg==
X-Received: by 2002:a2e:a22e:0:b0:2bc:ffbc:c1b4 with SMTP id i14-20020a2ea22e000000b002bcffbcc1b4mr6120167ljm.9.1693329099444;
        Tue, 29 Aug 2023 10:11:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b2a:b0:2b9:722f:8f69 with SMTP id
 b42-20020a05651c0b2a00b002b9722f8f69ls514714ljr.1.-pod-prod-03-eu; Tue, 29
 Aug 2023 10:11:38 -0700 (PDT)
X-Received: by 2002:a2e:7e10:0:b0:2b9:eaa7:c23f with SMTP id z16-20020a2e7e10000000b002b9eaa7c23fmr19811191ljc.49.1693329097903;
        Tue, 29 Aug 2023 10:11:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693329097; cv=none;
        d=google.com; s=arc-20160816;
        b=jNF0qoGDH3JMB9zr8i6aTXBCPt888Szi6umdZqcsj1JHmF7v5MijBHufVV7glRQOlr
         FOwiUT9YufwZsE0/rB4Ih0IR6xanZAu78M7iF7jtQbJbznfBRxgqasglTtI8txBhbyTA
         YPh9oX60KtHaVDZ+vEm/RByvAln7dgLugugJd0wtr7AJkETAmf6WIkCrPZixHVObHh60
         Nem4XsUBph8d70nOsdT8lAK1x/fGq+HnixUMxWKeQECX6dO2FHa5zYGAbOPuTWUCIjFW
         Hg6gxJpTB/oH/SsMahWrdHzC80BBhgrDp6qqQdw4qepALhNY54iQmr0/qofzOigQrInD
         K5WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=J9x0A1WNFQDshCpK/emmSalBuss8B7zIgs4IPlFr17A=;
        fh=J1Qt2dYQZwHfoASHEf8Q1j6KnDtpzzpCUlDsDM7WT0M=;
        b=rGwYw6OIVzjZ10LZd77I+Rsczw92z8EF86JX87L/r1RuOcC1CHBtIC3PYMirJUpg2p
         XYp7Z5ZPqlsVK5rvDuzrrMhnNFMarXuZkJRTM5zZWIeu5AoqZy8sFF9vSo3SmVfKuwwe
         EvS2MNNpeyLfJ5Kw3OLiL8J4ZL1UCvPvCdeZF9hVvIiNJmNyHzaNisBDqRCpdK9EA/0l
         uLgiEKft2bCM0jPCSYby2/FDtJ5Scga2GZ7a8vngeuf9dFjarfSDqTuK41OXTQJkTYFU
         dsCM1yB+CDjuWd/qSLqsyfUEJFC4ZVHlRk++CSzCoVcG8XdZ8r4+GD5GX//8jUDZbk6u
         MNBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FdmqrQoR;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.248 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-248.mta1.migadu.com (out-248.mta1.migadu.com. [95.215.58.248])
        by gmr-mx.google.com with ESMTPS id i24-20020a2e5418000000b002b9e701adbfsi1120069ljb.1.2023.08.29.10.11.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Aug 2023 10:11:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.248 as permitted sender) client-ip=95.215.58.248;
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
Subject: [PATCH 03/15] stackdepot: drop valid bit from handles
Date: Tue, 29 Aug 2023 19:11:13 +0200
Message-Id: <eade4ff3e44769fc172e782a829853127c644737.1693328501.git.andreyknvl@google.com>
In-Reply-To: <cover.1693328501.git.andreyknvl@google.com>
References: <cover.1693328501.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FdmqrQoR;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.248 as
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

Stack depot doesn't use the valid bit in handles in any way, so drop it.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 7 ++-----
 1 file changed, 2 insertions(+), 5 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0772125efe8a..482eac40791e 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -32,13 +32,12 @@
 
 #define DEPOT_HANDLE_BITS (sizeof(depot_stack_handle_t) * 8)
 
-#define DEPOT_VALID_BITS 1
 #define DEPOT_POOL_ORDER 2 /* Pool size order, 4 pages */
 #define DEPOT_POOL_SIZE (1LL << (PAGE_SHIFT + DEPOT_POOL_ORDER))
 #define DEPOT_STACK_ALIGN 4
 #define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
-#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_VALID_BITS - \
-			       DEPOT_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
+#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
+			       STACK_DEPOT_EXTRA_BITS)
 #define DEPOT_POOLS_CAP 8192
 #define DEPOT_MAX_POOLS \
 	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
@@ -50,7 +49,6 @@ union handle_parts {
 	struct {
 		u32 pool_index	: DEPOT_POOL_INDEX_BITS;
 		u32 offset	: DEPOT_OFFSET_BITS;
-		u32 valid	: DEPOT_VALID_BITS;
 		u32 extra	: STACK_DEPOT_EXTRA_BITS;
 	};
 };
@@ -303,7 +301,6 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	stack->size = size;
 	stack->handle.pool_index = pool_index;
 	stack->handle.offset = pool_offset >> DEPOT_STACK_ALIGN;
-	stack->handle.valid = 1;
 	stack->handle.extra = 0;
 	memcpy(stack->entries, entries, flex_array_size(stack, entries, size));
 	pool_offset += required_size;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eade4ff3e44769fc172e782a829853127c644737.1693328501.git.andreyknvl%40google.com.
