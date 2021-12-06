Return-Path: <kasan-dev+bncBAABBBEJXKGQMGQEKB7DBRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 45C7746AABB
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:41 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id d26-20020ac244da000000b00417e1d212a2sf4392828lfm.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827140; cv=pass;
        d=google.com; s=arc-20160816;
        b=gDUdNbaj10lDPNp2MvJF5ONqwHa+AOKGjNDjhgjb35I5y/BPYXr8GkIR+SBNVZ5k6U
         vyskKblogWr/d1q5g8plE4dppBnw+sM/BIVHXMrR8DH32hpWSXhHP+bBPrT8Czl2/zbt
         W8SkNgx18ZpFMP7y/TfpnxX1ZKfCfpZrbMg77UDDTBcLXGrvToe/HZifcPFpoS2+ym8W
         ymk5RDPmsMDRXN9GwtbrMBXH9Dgsxi1OVNGU49f60K7Q+unpnlOJXPQDmQWDp3CfUXHH
         BagPoxLtvSEGZJihTyFLsaS+YVFXrnQfYAl1dCbm1csfpyPnxOwQ+2BuSaxnZrmis7wc
         rG6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pBtTp7Gvri9Pp6E3ICLNne554MDPmtLgpY6TfHgEUV8=;
        b=SY82aHQBgCAMW35AxkcOmj9eqdgFawYHJznqS5WJkde4PgslDroKCnVIbeQMHFWLKq
         GmwVU6DVt240LabgxroPH81XDOUzt6878qFnuNQoaLu6PITvLvl7zU0oTbPlhItCihwo
         tM76AXaDxJypTJFEg8B5SoXV2EacuyI12D1VFizU7uVvC+y49e4ME9ec9CmASD/Y5fVm
         hfUDuHmIYbpgx6gKv4dRydpLaZ01aj78ScUWTCHZDt40md0cT3eiK9k745geKpE8HMoc
         9vJg2Ad0b88QibTXrpSVgQzf/qrCZUgM5X3nQeF/zNvH+K923V3lWV9nur6TIrLOBFlq
         RObg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WPYCRHJu;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pBtTp7Gvri9Pp6E3ICLNne554MDPmtLgpY6TfHgEUV8=;
        b=YeXAs5087pMpgB8EzYdydO/YcsKF1ekKaOPLW64lshVrXzLRMQ2YXWF8K5zdg3FE4A
         PCTHPiymesu4FKLttMGwNymEOA7TOC0Wnj/CXz8IySZxjGnZLfvjNa0z+tFnVthL06OP
         AKigEJRz0jz63lsSy8xxWbugXVEUd11mNzXWchaPsz6M9Y7nsg+RlzKdluLPlsFrzKji
         4nlObexzcxSCmR27XUbq+NnH8qfkHTBFZtXMRvq2m8rZcZECJ4HHz2kCMTIYS2tNOE3A
         8qSH/lNJmEN+PqKEM/cgOy8ifVi9p4sDRWPwWfUYD2P3i0Mq8I+c7rsfkPQU1OukvwU2
         2zaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pBtTp7Gvri9Pp6E3ICLNne554MDPmtLgpY6TfHgEUV8=;
        b=oNaa4Kp0gTu/t2aVU5k5IeUkQu9ica68/rSd9vBzYSu1jCXJc1Qup0oycerzEbbtek
         i6XGkqdcP9bq579WusjF3FraB7sCuxRJ0GhYcsU2W26+kMVm2cs1qvxQrGMVVZdCY5q3
         tBOHgifuppwXuIfQ2tJWldxmlTccIJ80RZYAtxOkt3Wr1YHTq43qrW8f3iIH6otWmBtT
         BX5tGXHiT4XGSL7R8L/ZbrTclgtXV+9ap8zAH4MwXjEqx2l8UzK8YQssopacPKwmAVeM
         6teNdxvM6d0gE6GL3d1/k9P2O3KoU2hZhBikE6kNtLMUz5oJbcGfgHOKIE8yOzUy59mA
         Vl5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bc1EdIvvJ3VF8PbtBR8OC8ZW8RcDs2uRoXXB4XGpH/HqIa1tj
	nwf+v/Z3TY9ZmH9jx0dGPI0=
X-Google-Smtp-Source: ABdhPJz1kueq73gwHQDtxjfmOhjezVkM/uu7TQnkL27geyaD2ZMx8HiLiIp+07e0hVqSSO/An+kUvA==
X-Received: by 2002:ac2:4423:: with SMTP id w3mr37357048lfl.385.1638827140862;
        Mon, 06 Dec 2021 13:45:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls1927781lfu.2.gmail; Mon,
 06 Dec 2021 13:45:40 -0800 (PST)
X-Received: by 2002:a05:6512:3e14:: with SMTP id i20mr38128195lfv.592.1638827140175;
        Mon, 06 Dec 2021 13:45:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827140; cv=none;
        d=google.com; s=arc-20160816;
        b=n+/b8634+3j0LZ06P/gpFP1Ww1IicPerCuaQ0JOnJV4QZzWgtcMPEAgP64/TanFHXJ
         +T4Mv17qO0nG+npgtElwAdV68mngsJajFFxlYPnu9QByJan/uAXQz2KVWdwX5r+g64Y+
         W1ZhDCxUyvOOuW9Ii5g4oCG7OEiiznLKacmiDoAIF60QECHa5E92D/deBc4vl9foAH2r
         /nSQjpid9irTk1bzcPjt43YeX8frd4rOhbzmoRdE7CtcTgEdYB5XAdeugWbw+7epkn+K
         Gqan66bbyD+RcaplysjJ63UX9ZsgAXC8c4PRMpG7inNUfuxIy/lq7MiiXQvJCD+cmP7x
         AHsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XbhL8TrmzwL9tq/+XeKdOp7BHc1RVFQ8fUYh+mFdIuI=;
        b=V1MbC2S/rkhImixgpRuKL0GmTQ7tIWXQM8FKpD9khqkJzg3bMg2+uR7tMFpt/NJgeE
         zC/m+TbLLf/IIz5oDs72S8Fs5cykqDFVLp4t3NhkIooFciVI7uknnYpyi2OsQ92roZDw
         +9dQ4KasudSv0n5vOCvyyXCWszZmxhMoeEZSJPxbGqeABpqadJWXylWRQYUjt79NRpei
         ZXJZLmhcfDYDOHuzOS9c1/IaTYiBxjzP1IK9ZG3DHI1sUCyLRhAn+3L1bPVoVdGRoA5N
         pb136MrKWhfKzpsqvW581RiXwFfemM4OR2cz+avVo8vhpqky+Y5e2rVjkCoP/iYrn6YN
         SqeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WPYCRHJu;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id u19si820912ljl.5.2021.12.06.13.45.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:40 -0800 (PST)
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
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 16/34] kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
Date: Mon,  6 Dec 2021 22:43:53 +0100
Message-Id: <599ecad2c26832e053a248737207cb1a1e4ed039.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=WPYCRHJu;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/599ecad2c26832e053a248737207cb1a1e4ed039.1638825394.git.andreyknvl%40google.com.
