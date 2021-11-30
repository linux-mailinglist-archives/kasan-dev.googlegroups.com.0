Return-Path: <kasan-dev+bncBAABB36ATKGQMGQECUHNTZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A33234640EF
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:06:39 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id b142-20020a1c8094000000b0033f27b76819sf8283015wmd.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:06:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638309999; cv=pass;
        d=google.com; s=arc-20160816;
        b=pQCyiPksaHQEWMzVE5etVW3dTiD2xVnbNnYdixYDvXf7JlFxkO59lkkB4DaWIRfEi7
         NDdz/KXT6KVXh8KGTPo5N5w+hkXPkYM56ky/hQSY9mywD9vLyfHwWbyfCOqt9mIi5nrP
         KjT/wrRNkAcm0XuNdgO4c/26fEqa83O9oNWDIs4URhWKZNC8Hb4qpAiy3kDvahZHFpgN
         CIbtUEqp4pC9Rwvh/LnI1xGele8C7CIOKPCaT+LSXUBQJmO+bo4vkhFNRccvZa9wM/ok
         y4fkf6EYImYIFXb8sCFBdDa9MB/ydRTVS58ZvHE/gKWeOme59QCcCICr3OcjdIPvoWkD
         Xo0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RSS2Knxebdd+F+N5rG+rCyttNOVfR4ciMip+rj4VEeg=;
        b=jU/0IPQTxo1gXWauWfN2t0w3JL4annzFGwBt6mCB/TB0gas6+z01P7dvcywDV5AkrN
         UnI1DogKYoW9ikdVtp3Co29ig8b0ArMrmyS8OxWmQEZD5JPd5+rdjkcFJjaUegWV94uz
         ME+va6+v1r3QZ9ugcHWfBzC4llupTigR41/rLBL21HQ1/v/GlWkYP8h5OBVaHopKXxyw
         JBGZCD5c2iYGeBZraPlcMA75UOCC29XtLsoFzbQM6OgwjblRC3vwi4G1UX804A2u5q6p
         xtSWqKUWMNECqCO4iUwoz4vnwlS8DbmR5DpbWWr9aRCUalRRzuv+Ye/tqkj6TJSuzPvy
         bDag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rTHic+ui;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RSS2Knxebdd+F+N5rG+rCyttNOVfR4ciMip+rj4VEeg=;
        b=YdktCtOYBuILN4XnIktCsXGzG+qVpa6mtpsum5Z7CMo7ADxCWmhXqLg70T17T+vsJk
         9IznpSwtGMQdP8+jUCuGW6Kio98ScKxBbtc/b+lXc3LhV2fp7n0yny1A3rS1vQh4koCS
         WfqPkXjawp8Ibo+ueIjEE3hxn642TREUI/nqQhQTw716j3ETjKtXqBqm18ODz1F2Hajg
         zbwqlQ/v7BZjuFCc1iGEQ+t2EJwaJ27Vs+tQX5Ua0uUaxAOPe44CQ/60YXd/f8oPjHnQ
         zSnHAONDCcvFPOqLx+HLKF5qFA0n3G/DaF0AKDT+mwq57rdPCT3DzdrxvRWGvnJIM8XA
         yeiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RSS2Knxebdd+F+N5rG+rCyttNOVfR4ciMip+rj4VEeg=;
        b=sAfn8ReQy6KADdDJw2/ZhwBj00zJOrY2SR3dHiS7RxkEvzvJqy8WtBtE1ITk/Nt1Hl
         2/rYb2rBzTk9LyM4n6jroSUhxdIBxSEEvH9DtY6m11kWPE2ziH1NLyrEBGU6LXoTnFef
         rTFSnI2NgN5JCWYSkskfWq/jOLq20bzipkMJVXkD8iLl89ITeGbpxNlv7VZ+APdkGP47
         0vBbXRCFaG76TQg6R9XHwxdlYqaER7Uh46daJfj5BiNW2nPDTq2dqwmhAK2x6OU1NytC
         sd/mwk7m31oT8YPl6gL4+tv0K4vxAf+rBUaLLiZMpjCJI4rQ9LDG+ys4FQCm0m7czOdh
         PdzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jyjZ19GI2gguGN26qW5OfQ5Cwv0k2NqcW/NMS/lq200Sqsv8C
	75GIUIjGE7oZF4eNjw3vz9E=
X-Google-Smtp-Source: ABdhPJyO6h9V50muVfrmNB/kgqJ713ZW572+CKZEzBdMQ0eRsDwqyU5ofLB0+7JEYfQZswQveul1gA==
X-Received: by 2002:a1c:4e17:: with SMTP id g23mr1898688wmh.158.1638309999487;
        Tue, 30 Nov 2021 14:06:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls178573wrp.3.gmail; Tue, 30 Nov
 2021 14:06:38 -0800 (PST)
X-Received: by 2002:adf:edc6:: with SMTP id v6mr1860799wro.461.1638309998797;
        Tue, 30 Nov 2021 14:06:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638309998; cv=none;
        d=google.com; s=arc-20160816;
        b=i88ObqJMGHxVU7nfV6uubPoY2s3lYT59QxYOQCIJlJmvqt0EjfkDC1SfiqUXkfz+kC
         sv/7pbaDbeyhxxMk1yuFburhTBtHr1P91cfpBhQ47L1H6Nn4hE+s6jGWPqNmx+rs6Ash
         vsJilDryPhYs8mqI1qN1W80vCP4zwWGl1Q01WxvSjD2NDnFUOiP3lgu68W8mLSJ/tafV
         MdXZMDgF3o9GoZUDXHxKemOgI4swLGVwQdddtkkO5KkEvGjGoNmcrjJ3cciS4B0VGOy+
         8yZp/wgIomjXWYzby151GJ/h+N+4GgIPyhUFV5MtwkiBNWnb+8gxil5piD/YQBkOjvnY
         +j4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pxjwWPacm+/5s9n0kHhZDBwjPwmcQ9h5CfpbBNedfPY=;
        b=0Qz83UGciOkzsXFgwtrdAleiMbOp7YRSwZUbhJMTQUHXcygk2mQOhjwDuZFLKjPS4a
         Rq63XM9Vu53mL7gwxoYrBQXNSGZNnB8a7ECKtXLfD0gbHpTPN3bd/wHHF/lPWKWMF9wA
         CdX8NCVaiHTx9vlsciKSLHRmMkZNR+++9wO7qv7aKnanSYlb2iqpLPOW40as/9zskZ8r
         LuGrMr1BbCt9lmV0pFLaDp5W6NV6322ctNR8ziFo4F3GpP82270lLjbUtU0dqJbwbO+C
         uL+9dUHOyEB2C2452NLf3nXAjBrrUI4wBk+RqiT/72LDRv+Ulic8hqKzYUC0zSRZmPNv
         0sfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rTHic+ui;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id o29si801219wms.1.2021.11.30.14.06.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:06:38 -0800 (PST)
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
Subject: [PATCH 14/31] kasan: clean up metadata byte definitions
Date: Tue, 30 Nov 2021 23:06:36 +0100
Message-Id: <d016860626a1531c01991da74d2321a52df515dc.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rTHic+ui;       spf=pass
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

Most of the metadata byte values are only used for Generic KASAN.

Remove KASAN_KMALLOC_FREETRACK definition for !CONFIG_KASAN_GENERIC
case, and put it along with other metadata values for the Generic
mode under a corresponding ifdef.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index aebd8df86a1f..a50450160638 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -71,15 +71,16 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
 #define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
 #define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
-#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #else
 #define KASAN_FREE_PAGE         KASAN_TAG_INVALID
 #define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
 #define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
 #define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
-#define KASAN_KMALLOC_FREETRACK KASAN_TAG_INVALID
 #endif
 
+#ifdef CONFIG_KASAN_GENERIC
+
+#define KASAN_KMALLOC_FREETRACK 0xFA  /* object was freed and has free track set */
 #define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
 #define KASAN_VMALLOC_INVALID   0xF8  /* unallocated space in vmapped page */
 
@@ -110,6 +111,8 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_ABI_VERSION 1
 #endif
 
+#endif /* CONFIG_KASAN_GENERIC */
+
 /* Metadata layout customization. */
 #define META_BYTES_PER_BLOCK 1
 #define META_BLOCKS_PER_ROW 16
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d016860626a1531c01991da74d2321a52df515dc.1638308023.git.andreyknvl%40google.com.
