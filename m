Return-Path: <kasan-dev+bncBAABBKMBV6QAMGQE7VRRNQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B67DB6B55D9
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Mar 2023 00:43:38 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id l31-20020a05600c1d1f00b003e8626cdd42sf2404309wms.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 15:43:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678491818; cv=pass;
        d=google.com; s=arc-20160816;
        b=hG01Wif77HLB9/vTD066UIlQ4vYs0/0BzFFAiV8Ly4RTHeXD+1HC9C9hnnNGVgdjde
         dNoaM8URJdxFAkXthbgM8cg1gCUEWfuYQOtjoPkG7zxkwL4PMC3W2VA4ZHplaKmMNaje
         MEi8aB8035Blfd1qzM1euddmXOUvpAI5ODZKEPj03sVYSmdaXM5FI38k6KXpV/ckdZ2O
         sy+W05E3UiEbH4t8j5gDHkLT4WzAdGp3H/GymTY2JGrMzi0I3XfmfbjJOmqDmQB8ld7R
         abP1hP+9kc4G1OC0JytI3WeDVFNVngsjpRqgZ2xSZE2a9PcwJLjPf07v4Xon4Mq4rAbw
         jSbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=yROtEnw+qbN57Er0flONpPtLw7wWI8qZI2sa1jK62vM=;
        b=VMhPWa8ceLOHw45kGavlARRL9OkSqrHsf0K/7jywwEXiknpP9ZVw23mYcyz8xipGC6
         a3CTK238UyVi/fTf8PApwhgRontYWnwOvOPfgcAnCLRv5xFp8GFCIa6gF/HSTokh61Uq
         VZ/NRoAHfDfp/3V8NCi1irbIr7qj6HlZShG02NUt12c7uaQpI+7zUS1hckUBpYI4OUp9
         QPNc+TuSBC95gOK1ZmOtSHgPFf/xSRt9jFKeMxXKxz9TK1l+Wy/yFCOsdB9LetDqaVt4
         pAUlu84YJIzFykes7QSp/kdhEh0CIvmyZ6psNYe88n7+n3m2ElnE/AZQ0XZWUgzT+ERw
         NhwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UcgdJ+DJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.23 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678491818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=yROtEnw+qbN57Er0flONpPtLw7wWI8qZI2sa1jK62vM=;
        b=GODkecaMMUjdZuh03DDQnBByskexQLA8seae6aQCSAmgVlWcdCq5xAcCY2+ksnXSdE
         22A2AOwDzdclGfVIZO6t34QvVdYOknwjdoQSGbZyXTqX6uAdPK+Ta+1lz5IGajiiEKTo
         1Wct72ZDMy9nFZqVENOW4KGCGsWbB2nF3ZcKzpEC8Qq3ZpDhX4T5yF4HkP/Fhz37v/eg
         MetqyUfVrDeuhlw8511hylYiSnwagUuf9AlC1sXZNhheCS1rangV73vWe05Mjn+kC7Yv
         Z/DrDlTuFEzNfbR3NpZ8HfBMecjBlp9X/E9HS8yKuAxPc09wNflMfEhjYo58n1jSqXwV
         1akg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678491818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=yROtEnw+qbN57Er0flONpPtLw7wWI8qZI2sa1jK62vM=;
        b=HO6VfpM3luuX8RPR+iGy8z2vh5/EgMXNU8e9tijUhCcMwSmshOi0EIINd3yZSZq9sC
         nRu6v3QyZZ7atnimF3Zd6XvlMHJrsAWsLvE2eQAewYUM55r6Q13w1rn744Mi9nXF8ahK
         eZOFpSEjIxPoS9A22wFD8gU4sX5ERaUuS6/o9A5wV2eCtbm3xAodks81uhw/bF/eVghg
         OoOfkpiX7d9B1ZUPBx9a3C4uAGBbpXDkcwZVPajfYQqt4H8igEyEWTYUAIHmIsIw7s4g
         hoo1d1WKxh20fLtk+m2oepLKJdp1PO6GzorUw5oF1ZRHXdRziPBvH+IGBBN0tzqKMk1I
         hTxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU9aDX9/kdIjkd00ESb2xP53AMjrBdYaDmmcJCV94Tl3uqPucAL
	EjUs+UsFAzCVuA3Nlptx9Go=
X-Google-Smtp-Source: AK7set/JjZBkJWzezSHwbstFDeUDubFLYDhnvl3ZpSw/vs8Zj2bZyNBhY6mL3r+d3Aw8pjwzUjvgYg==
X-Received: by 2002:a05:600c:4f55:b0:3df:97a1:75e8 with SMTP id m21-20020a05600c4f5500b003df97a175e8mr1109623wmq.0.1678491818024;
        Fri, 10 Mar 2023 15:43:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b23:b0:3e2:1c34:a7c8 with SMTP id
 m35-20020a05600c3b2300b003e21c34a7c8ls5373521wms.1.-pod-canary-gmail; Fri, 10
 Mar 2023 15:43:37 -0800 (PST)
X-Received: by 2002:a05:600c:4709:b0:3eb:3998:36f1 with SMTP id v9-20020a05600c470900b003eb399836f1mr4409682wmo.41.1678491816946;
        Fri, 10 Mar 2023 15:43:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678491816; cv=none;
        d=google.com; s=arc-20160816;
        b=W4t+sQwd2v2efKHpH7Znpn/AyfkuPxLvp+sNsFGv1+saBkPRduFy9FSjCwGbBT0a8z
         vCWXXLONbTWoKP4MTHFIN8cX/CuNZ4crChCmMVkW8hRFAtKIp7G49G5h4OIHYfjmzb5w
         G8kbDXGCJGck0aUhuo/g4DivaSYvuqwAbrxRKR5H1VGGk4aHNV7F5TxEVZTq5ey/H6Ho
         MeKOjTJelpxX7O50d65Ve/69bacRi+UkrSNevUYBT7d/XTmQkFGxrzxKxhRhQG3WhVPn
         Z7ghXH1OwFO0yNOdNfePpHF3YI4M9lXMgIKxsRGw/djvARViUeBrFenjr/+NxJw2nkDT
         FoPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=z4DPZvfjlbyZR04Gs5VqWFFoeLvvcar/vhfVx7MEdnM=;
        b=RRUQmxm189r6Ti7Cjn9OY9SzeqMUisluRHCmJUMt7jLAbNqUKcjP7E/a4K8f3zUAE3
         7xKZ2q+W7/VToWhPCXfBbwNSJm7otPEOqhzaHQFUz5vDUZ7EtzXA3c27sy6RgE83nHA7
         Xj+BMlmN3lBY7UEybRQXgWUwbJ8bLpF+cPV5HittsqqCj2Q1XSd4gUqjSMyJ6FFLjKrg
         z2dvxSlw7EgtDFd4otOwJu43Pb0B57Ca03HfSzjGWHlydftHJNX6AJx/5WZ+7tSBrOhN
         y6vTEIU4n7RkatjEhSvxYdJaWneDm66CoDN6V1xLZscwcvdqAKwJn25GhtkZ5zUp/2gZ
         kogw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UcgdJ+DJ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.23 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-23.mta1.migadu.com (out-23.mta1.migadu.com. [95.215.58.23])
        by gmr-mx.google.com with ESMTPS id b4-20020a05600003c400b002c59bef13d2si49756wrg.8.2023.03.10.15.43.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Mar 2023 15:43:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.23 as permitted sender) client-ip=95.215.58.23;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Weizhao Ouyang <ouyangweizhao@zeku.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 1/5] kasan: drop empty tagging-related defines
Date: Sat, 11 Mar 2023 00:43:29 +0100
Message-Id: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UcgdJ+DJ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.23 as
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

mm/kasan/kasan.h provides a number of empty defines for a few
arch-specific tagging-related routines, in case the architecture code
didn't define them.

The original idea was to simplify integration in case another architecture
starts supporting memory tagging. However, right now, if any of those
routines are not provided by an architecture, Hardware Tag-Based KASAN
won't work.

Drop the empty defines, as it would be better to get compiler errors
rather than runtime crashes when adding support for a new architecture.

Also drop empty hw_enable_tagging_sync/async/asymm defines for
!CONFIG_KASAN_HW_TAGS case, as those are only used in mm/kasan/hw_tags.c.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 26 --------------------------
 1 file changed, 26 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a61eeee3095a..b1895526d02f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -395,28 +395,6 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #ifdef CONFIG_KASAN_HW_TAGS
 
-#ifndef arch_enable_tagging_sync
-#define arch_enable_tagging_sync()
-#endif
-#ifndef arch_enable_tagging_async
-#define arch_enable_tagging_async()
-#endif
-#ifndef arch_enable_tagging_asymm
-#define arch_enable_tagging_asymm()
-#endif
-#ifndef arch_force_async_tag_fault
-#define arch_force_async_tag_fault()
-#endif
-#ifndef arch_get_random_tag
-#define arch_get_random_tag()	(0xFF)
-#endif
-#ifndef arch_get_mem_tag
-#define arch_get_mem_tag(addr)	(0xFF)
-#endif
-#ifndef arch_set_mem_tag_range
-#define arch_set_mem_tag_range(addr, size, tag, init) ((void *)(addr))
-#endif
-
 #define hw_enable_tagging_sync()		arch_enable_tagging_sync()
 #define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_enable_tagging_asymm()		arch_enable_tagging_asymm()
@@ -430,10 +408,6 @@ void kasan_enable_tagging(void);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-#define hw_enable_tagging_sync()
-#define hw_enable_tagging_async()
-#define hw_enable_tagging_asymm()
-
 static inline void kasan_enable_tagging(void) { }
 
 #endif /* CONFIG_KASAN_HW_TAGS */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl%40google.com.
