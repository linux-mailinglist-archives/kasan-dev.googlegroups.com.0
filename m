Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO7ORT6QKGQE3U5VU3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id C8A262A7143
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:27 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id a130sf1722867wmf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532027; cv=pass;
        d=google.com; s=arc-20160816;
        b=B2T7/mV412BBu7s5Y1UJiXFOLHf/Z9MIKg6XXrnYOAaPwtGWa30UL2o1s/LEiaV2fG
         s35VnIjBbEHc6Wx2ekhWZj9Qz/Lqtu7YCpB8AY8ZIIdLi74xagUnj4Jl7k5BwiTp+sv4
         O5gJaVIXnPQBcFkEfyOU2yDjtoVUAgNTO6e99f9tXZVKQ+82kPmeGuprfByNE+tczLmy
         kw4Zl5tXhZN0fbAqRfgPtc1iy/FhlHgzsXTnXounNUvGew6Dkgps2SfoyKejxPocBTqc
         t6pCC8JrheP1SqMeUC95tcZBR7oYxAhQtGPiQd9f48nR7QSeI1BaX0MYKbt3nTZTjlvW
         ZrXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ttV5SD6fWA1TrLYGHHe/wYbdBcT3cUBfeQK11fa4LJE=;
        b=S4w19AO1JGQOlKe7hyB9ZEfY2yYKD9GuyTREV+Fjl+ahb/wHzoUUufRoffHWFcJ/z+
         AYYLkYF68O8bb3stGY7dU7GqhfBbNd16wmDpvPWpmuHgUgILbyUC03NDVoXyZDouDHCT
         oumeTIF4vkG7Maal8mRKfHPGMlNn0nkqzRM1oLSmHc2dFWU30DwEdbql7kyLT0X51vMr
         2GBliq9kvBNZVJnBqXDC7vOvm0Zfuw3o2QR1MNeF9PqvCM4gO92fM8TUASrzIjCAQWrd
         56rCluNUdI5Wm9op0gKwzc52zQhBAI/T9a2vWDjJXCAmtF2Am10arQFUA6aGB9rzTNzR
         LSvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mCfoY2cp;
       spf=pass (google.com: domain of 3ojejxwokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OjejXwoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ttV5SD6fWA1TrLYGHHe/wYbdBcT3cUBfeQK11fa4LJE=;
        b=G75iNvPvZIexp6hGvCOQnlOrYpXC7HF+sQsWAAEwmsJY8RDliVH8033EMNujiUGz4D
         kyVvvaDBZCdy6SArmgtUsHAEVRC6VH9qQ90FHVL7GdJQ8qDrZzg+NtiJwrOmNYpksHjk
         jSV+z8j4uxbcyNNtuzhXsz3JMcOAVgev+eV6WO4R1bvmjiz8a4IV94PiV6Azqff1Pxqz
         nu/eK1a+oNvJKgYv18bpvaszGKyCtd3lSJPYxNCrdn8bqwwJRq9sueKJGdHVHXHqPVsI
         orbtqBWMoc4ORDmjZejOCUzcRm86BrkT8h4A23thlUsrImM8CSjJ1Etd4mwnM6sOVZte
         hgzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ttV5SD6fWA1TrLYGHHe/wYbdBcT3cUBfeQK11fa4LJE=;
        b=Sml+RjlIg2wgpLmHIQC9oGslUQGqX8jr47oejZud7/zYMJ/6YI81oeUsaz7ZCxnmmT
         xghX6QgcnQBjmyJnhnc/N1X1ppJOOKmLrF8O35w9VbrwIwz9iQQEOeJywILCPA6/kuq5
         wOnd47gsl8LcjdeC5wX0quzQPbRMOCtehGFl7Ill1SATo5kby3L04TSGJmnvUZxKV1JR
         2sj0ocgYN2JfKobNrxne+QgzbTSiet+mkKLUU6XbKyzjam+EX7H1jDIx8qa/taIh/F7g
         TRkZrWzr0lRz9ZxiR5S5o4QnlCOCEsgtbqZA4XOjAG33lzQHwj1QXkglzOAr4ijz+qvt
         DIxQ==
X-Gm-Message-State: AOAM532jEpY+GmTdFWD+8Hgi49cAAoNSNwazm4OyVpicwO8fvFNTlOIo
	AL8fQNBEel9Mp76nQnxwBhk=
X-Google-Smtp-Source: ABdhPJzECARQ75EfcAPvUt55vR4V/j7xgBAtavuhRS3duH69l+QoGuOXKxu+qqklxhROj+gWcRFWxA==
X-Received: by 2002:a1c:9d02:: with SMTP id g2mr94154wme.110.1604532027611;
        Wed, 04 Nov 2020 15:20:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f00f:: with SMTP id j15ls4642943wro.2.gmail; Wed, 04 Nov
 2020 15:20:26 -0800 (PST)
X-Received: by 2002:adf:f103:: with SMTP id r3mr382790wro.153.1604532026806;
        Wed, 04 Nov 2020 15:20:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532026; cv=none;
        d=google.com; s=arc-20160816;
        b=mFlj2VyOINfS+vFQtbct03oApCSna2L15Er6ZlXRk37bwzsKHakNbII4LATVyLUHaw
         8oGloltjp48BCzfixWag20G3uzVPc4GHP2+PBvbNQs+29Uh4LR1zo0B9oBPWlcfOcOSv
         M5YfQ19evkOLYvC7LKASxJ8X5GCFcZ3B6wL4I/+LaUc2h7luoqOqhVl9sXyIHfOEdktW
         LCNY4szCF+I4tCSXlI35BwZW8ILAQes8T1FnKBYDMd3RiSz2nX50hDVfSm1ZGuN/3ZzU
         LO9uKD0YrD/CxDH8P+DxkWauzGULNw1LTv6MdcP1VwKBGBF2phjxcvuKGxjVQapAXgfi
         2d2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=G92npUQrDAzWi0FLCRrGsDUgO/xYzB+b9yo7BatUrLQ=;
        b=KzWLUxHQR5gbA6jOUUEzwT3rMomYsi1H8LDFWbp9CQ80sxXohf9qPhtVGW/PIkMtPA
         EuCwUr6uByT3b4kJXa4J28rtRBwtvBZ2X6IGNtyO6j4X7eeXUVuRWSxnuRN42vqCqI7q
         7xBtxCBWQHpoGC1fc3P4YetKuYSG+AbTEj15WLZ4ZxNl1QJYAwTI6dDIzLr+vpoYXEem
         qa1Ca7N1r+ZAhq4K7aylA3SHE7I3xD4U/qu06wsmP1GXzVpr0cct6bXFrFyz93omsRCK
         bI7mFkYiLsUa9aihuqH471ItmeFd16vkpgrgD11+w/AYuhpXCYc23AtGt1uGc+8d/EGt
         yN+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mCfoY2cp;
       spf=pass (google.com: domain of 3ojejxwokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OjejXwoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id j199si202713wmj.0.2020.11.04.15.20.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ojejxwokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y26so8215wmj.7
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:26 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c772:: with SMTP id
 x18mr38926wmk.185.1604532026477; Wed, 04 Nov 2020 15:20:26 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:48 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <3efc77f8b7ea2f0820524fddd4caf1a14fda94b9.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 33/43] arm64: kasan: Align allocations for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mCfoY2cp;       spf=pass
 (google.com: domain of 3ojejxwokctkviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3OjejXwoKCTkViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Hardware tag-based KASAN uses the memory tagging approach, which requires
all allocations to be aligned to the memory granule size. Align the
allocations to MTE_GRANULE_SIZE via ARCH_SLAB_MINALIGN when
CONFIG_KASAN_HW_TAGS is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I51ebd3f9645e6330e5a92973bf7c86b62d632c2b
---
 arch/arm64/include/asm/cache.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
index 63d43b5f82f6..77cbbe3625f2 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,6 +6,7 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
+#include <asm/mte-kasan.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
@@ -51,6 +52,8 @@
 
 #ifdef CONFIG_KASAN_SW_TAGS
 #define ARCH_SLAB_MINALIGN	(1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#elif defined(CONFIG_KASAN_HW_TAGS)
+#define ARCH_SLAB_MINALIGN	MTE_GRANULE_SIZE
 #endif
 
 #ifndef __ASSEMBLY__
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3efc77f8b7ea2f0820524fddd4caf1a14fda94b9.1604531793.git.andreyknvl%40google.com.
