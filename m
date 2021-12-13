Return-Path: <kasan-dev+bncBAABB2UB36GQMGQE4KTVNLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 11C894736D9
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:47 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id ay17-20020a05600c1e1100b0033f27b76819sf10283519wmb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432426; cv=pass;
        d=google.com; s=arc-20160816;
        b=VgjSRAp0+9O4atO/vOvMJ2ArhTVGHIqsevBQB05mIveS6cYRA4ieGLTLrAldBJkf1h
         EVBOrc1Vcyw8zbGoncOX1tOeTzk63KTcHG4jwnf901WFJJm6z9Nr3LMTFkvr5VIMx2bg
         jmepgcjFW0fKAT3K5tmEC+bRSuE2Y/VzDs6CCyyceUt2B/V7jZl9RGjBJUag3YhfjB98
         /q0pe0porfd/Svqz/crfP+y3+dkLrPuaJZ83DDOTCe+1KHE/zpy6gNZWjCxzxCPIx6Ju
         YfWYGdlUgbmeWowjTfWtzbbyrQDHIBQ5d0Psuros0dazC2axzY0ldeeRliQemJve4cXv
         hCZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KfuYRVQV4ZB7cNNKLARtOBcAnfpSdlCSPtGi9ScYUSE=;
        b=uiJdiw8GZcJrHJoU2dHU/vjzyJ/Q8WGg95lsEmhHptw1EjnmoDkrg7nUrsz+4ulb57
         OL0OgL6ZMwf3s+7DvoRetWuwAOgRxqli0HlHRXc1XGgzzVgX0HVvZ769RjEhpMApbS+6
         G7XsbAt17rdFBQVxSYV/2s/5ptNYSLnyAcd5OVvqF7jKqU5EsOoFtgcdjx0RyvuBOoar
         BHnyB0M0/AI8/vD3okhDfhGeYkDyPG5/8HTCglqLtGzlvCnBLzMZZmIrBH3U+zGyrPjY
         aR+TzxmllJVq/KukXZ9RLYdJLSdghjxPUbrLzJX1ThNYkYGEH5ro6Ws2Li3kEzo8a4zh
         pXPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MwuAVUv+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KfuYRVQV4ZB7cNNKLARtOBcAnfpSdlCSPtGi9ScYUSE=;
        b=GOGmcrMmG8Pvrk+aUNMikOc9Ulg9RfYOSRPAXJu+vF6rue81j6G5G5k0H6CN51gLkm
         4CFrouDeuSAPXjD43CuEW0GXKN6Yf+aoCgWf/gG+m0MiW8v39g51D5XgxSJlvwj9aCgU
         usLNL6H95e2R9DUdZLkys6Jt88wXfUhNtdLCZ6aJRJvH1i34LNLfmAcmdDFdXBJIpuby
         bCKX/nR4nZthMY+mZ2Oyf44/xKSZYfRgF1yOZNmHwFXKWAwexY1MIw1VmBGROJy+/308
         r0WHWvxTSYbH7uOkWGr6kjHW8gRFgAcFDc6pUHW6nvjXEdggR+4P57pCUna+mJvEQ2Pm
         HLNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KfuYRVQV4ZB7cNNKLARtOBcAnfpSdlCSPtGi9ScYUSE=;
        b=Jr1K/eOH6Q4jEaqen4O0pK8KQ83yuH/R4s7YCDri03U2j9IQuTuv0K05wSrymtCuM9
         AKFSflNgqnu0JrdGuHlUwFSr71HOGjZEAHKnGnuAwucVeNhiOVPcqGN6yq+e4Lr1agVG
         3Yf8R7e2fuUTaKW5M/d9VlHJaM43fG2wzBFm+pfVuhbnAK9WcxPWwds9ZCgWuCDnr99p
         U8TDsSH7Tq8v92KIOdFPjJYCTRUYbX+kjaxdv48Cd9TvVGxa3yQt1ITZfs9a7t8K26KK
         dkygMPbLdKb0iiiKfpljaUoiSvbniybtJPxjsIEgkHi+ezRjKy4aEf+lxI6Cb9824L6N
         hFrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XotimzcW+v1XcKBcAcorznmri+3jJXBWVJEQ+cxMmh6KHuZAs
	DvO3LC1Jw/xADQ+eK4pamcA=
X-Google-Smtp-Source: ABdhPJyBcFOyoxJ1PydxIDJtOTKVpyz38DY9Nhsu/lNbgiDSP3Dtuzx05fQEYSHcCuizeWi+urYOlA==
X-Received: by 2002:a05:600c:3c91:: with SMTP id bg17mr41523214wmb.80.1639432426858;
        Mon, 13 Dec 2021 13:53:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls500764wro.2.gmail; Mon, 13 Dec
 2021 13:53:46 -0800 (PST)
X-Received: by 2002:adf:f491:: with SMTP id l17mr1229590wro.525.1639432426102;
        Mon, 13 Dec 2021 13:53:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432426; cv=none;
        d=google.com; s=arc-20160816;
        b=l5NisudyITSDpFeD2i9yIj5iYp8zMV12DVeXCfPVlbt02coj2mxppXr985pcKz9Ppg
         XmzVs/t4OG5Y0Ky/XrcGr1o8gEyh9wp01DElSay3FPy2XqIuHbIVklSftcwZy1EvF8uo
         oq7jx7TwlJR6tacYd/whpw0V17OSv912+OPr8dSAPJbCNY2Fez4auWYqXka/y2zc6B6/
         e4+1DliGsG4MNjdeKbpaFgBMhPUArlomcULTKoEU/uOejNvWBC35+5thyKLi65c+3V+Y
         FsuTSxQcn7UgeH8SF1DJG6nXXs2mlnHwrHOUZktIgP4t1UeCxgGxNvR3upXkSrY6UfCa
         tCNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0IdRDXCa9SZcon1zPmMblGg7LqNmOr90G8zkdwtasy0=;
        b=DdG5dnKzLPIc8MluGLptNb/LHXGgos0amMJLLhXgwQl4QJBrVFb3B8G93ZPA+9Edo8
         3nUAgTvxZTuDVDRzwFvBLOFXGTDija6rSzUmSp+KuoNKPZk/HRmn4radZnFq1kUmrnmp
         5M0U9C95QjxI5wM5lNgp/oPApP5ATukFLsS3zOJdilG3kDXZc4UexMQMX+km6JAsI+84
         nj2ECmDCuiRIxx+BBw/Ta/moU3R9HXIiumu8LuutQnr4zn7rHvh6VDxZnjMz2hn69tHi
         9J9Ev9R9Um/OimpOGp/emCQvm73ukquSKvwaIGprXuaqeqot0oBhgleT7XsIYAGtCkE1
         uS+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=MwuAVUv+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id v14si585370wrd.6.2021.12.13.13.53.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 15/38] kasan: clean up metadata byte definitions
Date: Mon, 13 Dec 2021 22:53:05 +0100
Message-Id: <e82b75533a93a5fc85e24b782c6177457af0755d.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=MwuAVUv+;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Most of the metadata byte values are only used for Generic KASAN.

Remove KASAN_KMALLOC_FREETRACK definition for !CONFIG_KASAN_GENERIC
case, and put it along with other metadata values for the Generic
mode under a corresponding ifdef.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c17fa8d26ffe..952cd6f9ca46 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e82b75533a93a5fc85e24b782c6177457af0755d.1639432170.git.andreyknvl%40google.com.
