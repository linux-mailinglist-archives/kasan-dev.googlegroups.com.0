Return-Path: <kasan-dev+bncBAABBZUJXCHAMGQEBVQCMTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E8C24481F94
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:42 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id k11-20020a05651c0a0b00b0022dc4d55f14sf5502113ljq.22
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891622; cv=pass;
        d=google.com; s=arc-20160816;
        b=oTG8sWeJ5y+jcxdL7BpRWT7dVOSoMGhk+yQpODXzvTvm/6BffR0azef1S/+ITPtnSr
         gwd0svFm7Gc6VRm7h4YyeELDZt0DwKOtpEDCRSQO5WN/BWIE2jJ7hfnjvMKw9Ibnp9Gb
         UlbeLnUCeg/EFO4k3frEz0CcM7QYOUnmPKKHU6lSAMKLJ4dENEl5jUN9edUeox92hwf8
         GUGUQezah5EQCuwIKPg8J91ybUJBrBQeVLs+P/9BD26EgJqR73PNvR1xdTCujzNQh+L+
         r/Bf7RJwUmmx52JXm59z1dkvU3xU0F0xIpgiFfrkV3rDV4TwKfjG8YDA8txbVQKN0iiX
         9huQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YSjdvos2n8FHAwNsUOnwz+WasKVSvQaUcodLqWZA0p8=;
        b=vmOywlAo4whVPn5/IkZk0R7ssJFWS0WLSUoT4pqSVB9BWPOjG4NfRjr5q4x31no1f7
         v7/L3Hy9p5ta6qVS9j9OTa74TBuWym59eP8/FRFMR419WXnyLjRQkDP8FuCCq+AAamSJ
         U88HuCjTlxtYrGngtqWs/eirSRlIW1lPc5wMA96f7ZLAawXDKR+jgdUN4XlTuRBJMb8y
         5btrPCE8XiWqASUdidt/E2ZtA07/XbiAbnFW712xkKFjjJxBBRj8HLIdc6eUQjN9HBbq
         lYNRo0/TcBPHvs+uHjyWgtHcVdDHcQkrCiWX4cyLersFl4x1v2tSgYjOFno4WQb57ABP
         ACrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Fdr1CYMB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YSjdvos2n8FHAwNsUOnwz+WasKVSvQaUcodLqWZA0p8=;
        b=GfJmTNN0slpv23LRABq8T6dqktAFSwYz4IczPgA0GlEbyKGuibt6pZVEZlQlgPFpby
         wMqdHUMwb5n4z/wpmFgSVmDIQzXEMkObgb4Cxrv2Dxx6xZJSJBEr0sB+zvrmM7rmPIPj
         /MQMwJQ+jck096CuTu2Z13+6aXo7l7/Odmoy+AYvyEY33sYWhA/vOHKCSSU/3xVASEgk
         NLKCKy2KqWijtCMUvCT2SM2WIEKeupu5subOq13a6bKpkCVcLDL8Y5fkO74IOCpVBjfn
         ZU8E4FDkSBDHmgVA4UJhZFQqVZErSYBdM+llcrFUT1h0kk7eKohTkVuKhyy9EZDEhaJ2
         X5wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YSjdvos2n8FHAwNsUOnwz+WasKVSvQaUcodLqWZA0p8=;
        b=IRmQDZTmaX7Rsga+XrxXj+etoEdFB8Hz5KvZd7M0XhceDOFVmKh8JMN5dw2LKoJ+lV
         jLbetawIsxrQtkvazrdNWXipKP24EojIo/r/uaYV7su2whLWDvQSSVftCBHvw7J25crc
         Hw+zlZgqAqulHUA9ZPYBM34wF29bvlP5lKbnT6VM68GZD5y8NFcaTMxVNolurvzDmU/Z
         BqnhDDWaBFN5xTkohks75nwCcFTgbhu3hQf2zeCTJmSc/u0E3+KZwH6vwjyj6Eixr6h8
         og/eG5FtO8ox1Yxjj8LTT1nF9RoQAMXe1zxC3TRamjXHVeJZuI/IUT+xkBkSfk7NEY9R
         rTGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XSHWMwH0K7HRmbinj1n8ycjnlYxubiLoA5POFfEuab1VYv2Yh
	R9OCm+DL9Ko77yCPj6JLN7g=
X-Google-Smtp-Source: ABdhPJzPIr95SLgkP6LekNJFJDYY/s6TJIif1C9zvoZSW/aZisQy6qYDhMch1Qidnt0C0JGUJ4gCbg==
X-Received: by 2002:a05:6512:3e0e:: with SMTP id i14mr10996540lfv.581.1640891622556;
        Thu, 30 Dec 2021 11:13:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:198a:: with SMTP id bx10ls2477015ljb.7.gmail; Thu,
 30 Dec 2021 11:13:41 -0800 (PST)
X-Received: by 2002:a2e:88d4:: with SMTP id a20mr27470001ljk.218.1640891621472;
        Thu, 30 Dec 2021 11:13:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891621; cv=none;
        d=google.com; s=arc-20160816;
        b=r5yK/uOrtA4LBarIzyBkXeAcIO44h40JL+oY2wNwOCvV5fyYQj8lJW0HpWyUE3QMbI
         v7EDf/g3Zr9vthuX6f+NMc+AxBNLUk2ZdajUVVPdbKYLsHFL3pDnFrr39ahiGGBBOBrs
         v7AeAPlOyUwfSoEQw9Z3J5RD9+7KIP1COZ83i9A0gnfKkqOlusa/HBBx12AU4jxlGcd5
         4vjtkN9N5NLmPWa+70i2g8qhh7IIsRes3QPXfRqs+JFdZMyARKuYDv5LLta8ptMQQbJ3
         1HG1Cma1E2B8uXTHpbCKdkKFDCt2xBcopsme1zNC1w8xqiKW8nwTChRQiwr8bB1+r0mv
         iv0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Kp+2Q3QLxWnCUmTGCUqJeVTafIKYNKQMJyZMylxx2h8=;
        b=uoJdHwHz9tPLnremCeC6/+Gckmij/KfK8Mq+3mogaqa7kwGJvoGgd/R7kVDeHCCLJ8
         KCXAqu1cKfqsLLB21q0fi9C7pLRbC9Ehl5qgrCwRQkr8ElyXN0wIuGTKOoHv32t7aY4z
         6Y9Rp4PSZVVMK23psOO8aPg4AuE+teWUZos5y5V7+K1RBAwRP68RSyJ+pQ9Ai1+Qnidk
         8LcP5iUf/S6irYF22CyRnQ0RWqGsfiZHDiT3D9JAn/CxJhwuw/wLqKK7EvCfcvH5B/Ce
         guqwImf3eDoKt/mbYeAoyvom9Z/JNNuon5kyHxKh9B7ndQAaQCc5wGokgyqplXGF4Lzz
         OZmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Fdr1CYMB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id i3si1000673ljd.3.2021.12.30.11.13.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH mm v5 16/39] kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
Date: Thu, 30 Dec 2021 20:12:18 +0100
Message-Id: <cc2b1a31579bbeb125a7868369501ad8edb629f1.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Fdr1CYMB;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 mm/kasan/kasan.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 952cd6f9ca46..020f3e57a03f 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cc2b1a31579bbeb125a7868369501ad8edb629f1.1640891329.git.andreyknvl%40google.com.
