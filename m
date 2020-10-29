Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWNO5T6AKGQEYBUKCHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 492DB29F4E1
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:19 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id i11sf1774135pgi.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999578; cv=pass;
        d=google.com; s=arc-20160816;
        b=qZz6uw9zN8RIRkK1AuJWylMBgr8ZqLyH77kBZ1LdzkgxMKVoWXZ52oQPiU8HjJIK3g
         l33zH8wtUL0O+ps/8GgDFOmIwPC1OQ7ODBx7iYdjsT2zgeMekkGpW9ZUljGOF3GKzS0Y
         K6rQkcHKb7gN9acwF8BzXbWJcFjwom7uWR5SSHcgp5GYVV9WNsn4Hy0Ar/xGPRxv0IkG
         Cf0Bxighca8BgstuIKv2qGUPpHsDWyQQCO8nnWBCICVW6vr+fMXNixHQFyWmZw4fudqZ
         5VTz/9BfjjpfeVnnR8EOMLLmZW74Duud6yC9jWQukQefVcdcXc5SEJ0zMbch4PS+olTa
         xSxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=28LMzCRTwGAFoZKJwiUYoifXiUcUU06hMi3YS3o7xgA=;
        b=JDGEPuCSJzYW2AuZRk+Y1JE5AW8qHux0quKaeedpio4ZKwOtbbrNGNY/F5/gcca//e
         cXtmtEuonlGWAOq4Oi4ijywfvtBlCvpesOonb/d/hKBnCfi1VjAypl8eJwawbyv0CVcK
         pY+ub3REt61IggpkoOIF2NogVxFbh9hFJSjAxjAZZKcP2OE0bDdeelkWIZbS9yAqljOt
         OD9WdqUY3JPBMOXDvTFGLPSyNS4fR1fCFvYKjCgQYXy/hZqVR0wOxOyn2MMVTshtOzOf
         0KO9OES138JsKGsNcobEJkjTuaDu8hsqVA19XEGqROHSWaBvdsPJj6w4c+Tn9/1aaM0Z
         vHXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FcdRk45x;
       spf=pass (google.com: domain of 3wbebxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3WBebXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=28LMzCRTwGAFoZKJwiUYoifXiUcUU06hMi3YS3o7xgA=;
        b=Z5/uUBU2zi+Td3ppLDKTKFGWu7sCdp/9hkEPyktIvvorq5EmlHln90Rxsa9QpB8EEV
         BL/gQjG7V+Ngsu9mimTlgvGfsvm3BP1/br3MD6qAvJAlE7Qsp0MCD3fHj9F9XCM/Vo+Y
         7ttXy26WzXNlehM2Kb5U+B8YgX6NM8dy5juI9Gxeh3fgJ4hoCIZaj9jJ83yWVMoYasTa
         xhUAw3ug/JIA13X0GRoXiLfmJjec62rkZH+sFG9y/U3Aul6U21rPquXaOigQQ3g8Z5x2
         jR0Sx1xdd1qU3dBhI1hgOuUp1HPVwCNjMidYdBYNaxTAOWxTvz9aNL9IL2uqzLnhx6Yb
         EHdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=28LMzCRTwGAFoZKJwiUYoifXiUcUU06hMi3YS3o7xgA=;
        b=PV3x3THWcWmeAUIkodAcaV4t7v/W3ZeIOW6G9shyKH8Ku0S77QEJkc41mF2HXCn9tl
         lYkkbETMLjbakBSKRMsGCXtGRZHOvVk1Mrj66fcVhFKmtREcvy0b0qzROFtyMnJ3J7Y5
         7eY0XQWb/uRGfN6dw2k2PKAheTgTzblRsHgEmpwkROd7s6nyEG0y2bixomRBtmNBqM4X
         3mExaMD2Cs+4HqmJvRLQtoWIXwpfw21jFOL7CUr/SwjVC7dPaSjLnFZl+eGBI3ZnVyNO
         Qa1yKTpvrOrKRIAF554G2m4FPhinwnmjGsEgewIM04ttY0kMbp7Lj7hWBtADW8/tcSsB
         ht1g==
X-Gm-Message-State: AOAM532+CeEPUhU7LOuTHQFvyiWbJhO4gYtuk+ZwGXSseqZruJe5D9mC
	A9Pf1JRHXR1lvKA1p2gQWW8=
X-Google-Smtp-Source: ABdhPJxEfR8q9adLjJ8cBblh3QC/jpJg9xngHROkHjj7lISCV0GFSESt4G2YbnKhlwJOzQNNAHvJ1g==
X-Received: by 2002:a63:7c54:: with SMTP id l20mr5235030pgn.151.1603999577885;
        Thu, 29 Oct 2020 12:26:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7607:: with SMTP id k7ls1678148pll.10.gmail; Thu, 29
 Oct 2020 12:26:17 -0700 (PDT)
X-Received: by 2002:a17:90a:6683:: with SMTP id m3mr682275pjj.225.1603999577313;
        Thu, 29 Oct 2020 12:26:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999577; cv=none;
        d=google.com; s=arc-20160816;
        b=TQdVlpo/Qhq9YMvJe91caZTbrnfKinroE7E90HF4+NFg0+bKrMLnXGJR+PnvkPC+4L
         lDj9pOnWmrhttvrYXYu+nJcmZE1BxBbsiPQ9owX7KgimJDZ7xQlQBBQPtDF1HYUawEiN
         3Ss2gNXYXrO888b4t/UZ9VlxPZSHst88uBzD2dVg8J8Cp2XbqSnET1hIhbMUTUkeqkzl
         vxvFUZefAKd2gFq+0cDoNu7TyI7yqMA+9vCAv9nxdpuN6/e+mt3R3ZQ/Ystu5E36gRku
         Vc5ymglAWfukNCbwlwRZakJGPtbdj4SbdwIWGvu6zcBjDZEC0gyaI2pbePO1wH4hECAz
         q4gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=H80qO4w/VNIyZFliU/RvriPpJf0TWzdH6o9fbTX/riQ=;
        b=b09EoEJZvDZbDOxGiN2soi2yruRBHUMEbVxpYpuk1yaIHGSwrax8jfqmO+XgAROM2Y
         3nhPRY5YD4/3EusaZnhjqw3hD4RP15h+XkDECYN+Fo/3GAgOPgHSex67Kl8g95GXyobb
         WZD2je7lntB6eBAhHliQGaXxUkZTLSu/0bqNUU26p/nVknGbD8s0cHS+0ku7EM/RLKz1
         /HXnwMTvgQe1bviZEtT/1PlVAfvo1KUte4IkxWIr3bRa/IYega1znGDXWOFgABhEPh0A
         H2qBxPb0rp5pxhkqItGq1JqpaI0bNVF+KvJEOxd3S2YOZGaFFPQyx3P6kpYx9ojnIHtG
         7mnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FcdRk45x;
       spf=pass (google.com: domain of 3wbebxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3WBebXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id v24si253776plo.1.2020.10.29.12.26.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wbebxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d6so2541904qtp.2
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:17 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:59cf:: with SMTP id
 el15mr6145700qvb.17.1603999576430; Thu, 29 Oct 2020 12:26:16 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:25 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <cc9e445314fc99b1aeee347c6a9b99f0a6e37d23.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 04/40] arm64: kasan: Add arch layer for memory tagging helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FcdRk45x;       spf=pass
 (google.com: domain of 3wbebxwokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3WBebXwoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
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

This patch add a set of arch_*() memory tagging helpers currently only
defined for arm64 when hardware tag-based KASAN is enabled. These helpers
will be used by KASAN runtime to implement the hardware tag-based mode.

The arch-level indirection level is introduced to simplify adding hardware
tag-based KASAN support for other architectures in the future by defining
the appropriate arch_*() macros.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
---
 arch/arm64/include/asm/memory.h |  8 ++++++++
 mm/kasan/kasan.h                | 18 ++++++++++++++++++
 2 files changed, 26 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index cd61239bae8c..580d6ef17079 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -230,6 +230,14 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 	return (const void *)(__addr | __tag_shifted(tag));
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define arch_init_tags(max_tag)			mte_init_tags(max_tag)
+#define arch_get_random_tag()			mte_get_random_tag()
+#define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
+#define arch_set_mem_tag_range(addr, size, tag)	\
+			mte_set_mem_tag_range((addr), (size), (tag))
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Physical vs virtual RAM address space conversion.  These are
  * private definitions which should NOT be used outside memory.h
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ac499456740f..633f8902e5e2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -224,6 +224,24 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifndef arch_init_tags
+#define arch_init_tags(max_tag)
+#endif
+#ifndef arch_get_random_tag
+#define arch_get_random_tag()	(0xFF)
+#endif
+#ifndef arch_get_mem_tag
+#define arch_get_mem_tag(addr)	(0xFF)
+#endif
+#ifndef arch_set_mem_tag_range
+#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
+#endif
+
+#define init_tags(max_tag)			arch_init_tags(max_tag)
+#define get_random_tag()			arch_get_random_tag()
+#define get_mem_tag(addr)			arch_get_mem_tag(addr)
+#define set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cc9e445314fc99b1aeee347c6a9b99f0a6e37d23.1603999489.git.andreyknvl%40google.com.
