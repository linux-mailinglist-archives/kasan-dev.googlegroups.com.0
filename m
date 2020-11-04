Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPXORT6QKGQEPOVL25Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 088AD2A7145
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:31 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id h14sf97267lfl.20
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532030; cv=pass;
        d=google.com; s=arc-20160816;
        b=h5uGC/ybv859Kptl/nvbBRcHjWMj1PDovjU4jEurYGcIfz0m3sH8em58KrcNzmlK55
         eVnyQGqXbZgOat8xF3H/Y0rW/BlAprsi3lQBiG9GONEQNHSLj2XrP6KomV2pCh5PMDFw
         N4/3hkPW4Wl3VteCTUXnETZGnYQaNXY07Hi6ikEWUL2V/IRmHpfw6eb4b0omSY/oNGIC
         iC0fSO/VMcsO/viA6PXqhLu6ckGgfJ9Yn9rQ6G31t+YGkfGhUwSVcIHSKypb8Sb4DuKR
         lb+dH0b6S6SwR+s25ltORTU+LQ0rwFHm588WvU3r/OxFyh/yg0qzO+CxLdNylEPSYub7
         6lWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=kkaKFljrSX79igcZIk+DM/MGbF0H9/0onm/+HB5L0kw=;
        b=PPj4O91HxhImfJnr9PTQJCbItcAQWGwu/Al9ePVqsdaSeZ7J6B3SA717877KVcJhYa
         y72DCZEryOI5FgOP8dRBuxpA11YzYYwkeJiuCRdHJYyiLOeQS3easi+SRDfe3KfW1iet
         2Ii3iraHDWUS9LawJN7PrgnwlcsNsMoML9a1bfBlmiNaM2Vgqwl/vIbQBV4Xi9bgiMKm
         br1DB/Is1d9Bry8J/sWE6tbIbXXlwAH+MASLPesWnjGvlKGV08fDR/0yV9ia5BgELY21
         r0stbbdw3Q9x5mA/SFF97+0+V34pdqfRhngIQTI8qP0Wk27y9jzNFGZLWokTrAs7NWiD
         80/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MDmPTXJQ;
       spf=pass (google.com: domain of 3pdejxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3PDejXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kkaKFljrSX79igcZIk+DM/MGbF0H9/0onm/+HB5L0kw=;
        b=IBJMmF/vdVkE3TQxWGGC0YiS07bEDG6BGAHg2u4Sa6gw6Efl47itFbM+LWMevYydQa
         2L9MHuWlS321fYdrIT8IHp4We8GOG+AtChLROGC3igrLtAyOQ099YxbkXACgzXAMbzQG
         qqz9gI86jGt3bEjLP5JmeawqGa0rqp66tBbqagi2oMFoXzE441Po4YTD7kJolBORSwCR
         7DX4HTQAjR8tZY1tGmd1YPKtGX3o4FdLZpm81gCEZ9szZ73pTCwB1GeRkUrU8JDJKxPQ
         3i5pHd7CNmEwqVDgnAdPj123An3O7x97BVPXqaZ7M8MWCoRBrwjXId1dR8sgzo/1oTtR
         Qa6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kkaKFljrSX79igcZIk+DM/MGbF0H9/0onm/+HB5L0kw=;
        b=fJgPWVYeKJNjANCmUv0ti2l7etyLDa272DyvCxccDi7/laKDNmZCo/6dyhrIma2lny
         pxlU0wjrrVQmu/5kvsXXegVT7jf5XStEB50N7yp6bhGzrU/Q8bTKuua0BxwDlumwLgnT
         irXOVKiPSIspby9s3WdyKflDZxQK6DlDvKcJuGMNP1ZIyH3yAXFBssiAnw6XV6U9N+Fd
         cjvV6CJggdI3YoLHLe57Lpf/2whMpsi4RJ4khnrZF4iHf58GP13Rv+VjdgYr5ZjPqnkM
         NL8qhYoVmZlkH5ZFgM7kSA8jMt7a2n2Hi0/2QeOFGWdu4x2GzIXoP1wycOH8ax4sfFBr
         5/EQ==
X-Gm-Message-State: AOAM532ZTAkGTDNQ7A/V6qSgGPpksLn3Ww9OjUdgcAb71QmpaA1+YqjX
	S1ycmluLEUCCteMpcvqRui0=
X-Google-Smtp-Source: ABdhPJxQoCOGXNUpwlCYoCP5DWlL8fXTGjIdXGqY5+e9VvH8y1gnjMrZbbY4PH5NdwXEanOtB7Ezgw==
X-Received: by 2002:ac2:5466:: with SMTP id e6mr24378lfn.17.1604532030599;
        Wed, 04 Nov 2020 15:20:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2023:: with SMTP id s3ls2260259lfs.0.gmail; Wed, 04
 Nov 2020 15:20:29 -0800 (PST)
X-Received: by 2002:a05:6512:cc:: with SMTP id c12mr13864lfp.373.1604532029578;
        Wed, 04 Nov 2020 15:20:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532029; cv=none;
        d=google.com; s=arc-20160816;
        b=elltY7BVAbWVU45Hd4vnXNApF1P6r2XVc+m1eJO7/wcGBy0wZUbOjtehzMnoCLwlMG
         nZsSMpAFiWc7btYCa9ElUACW+oDhlJZsu4UUeeJqnauxH0TZSfVJJGXIbdyCiaJWpY+b
         ljRtlrRZRsjBGTZcxWQwHzFTI5eBnHuWkQuHCWBuxoABBa29LFE+i+i5t/eU/5GdDy6d
         G/3AVkFLhTdvlOEUNsjHq7JRC6hU1a7qoHg5y5XploPByvSCEzjbHkj0xRMBOdCNB5Xp
         RKIKJb/fKwKYAz1DhsHztYXrzxsGUwqVq0X4olxvnvVN9I5Sh6ZfTZ5ooR1A/nMqQryp
         g2fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VwB+r0G+nQxE1tuBjegw7DUOaY0AiMb9tMmTZBhg6+8=;
        b=WA6aFnTHJPRPu+m0toI/ZXAWPV48C/yJ0ppluy158EU1hkHw4V9Q7CHCLEeqShWqw3
         QAsVfTcW1TXWvb5JHSAltfj70K4REp19+68kJe883zv8UInXFyYzZOS6E1jlxgt0KWo2
         +qwhAZcS6eMyEnF2JdZFic6VABsHB1uGlt7bkbCWn9ckhKgHKkzvBe5TIA/q4/2ds/pd
         +5lftkWZW1yuBDrBAAqih+UtJBxX8nrhUpeSUueoTqEQqYPG33QpTWxSqtgA6kRWNKDQ
         pjBBQwa7nykZD5/ujSuv6F3t1d7iZUZFt1cyiil6BJUIIILnxMjRcMf3pgA4k2QrKV2z
         QkfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MDmPTXJQ;
       spf=pass (google.com: domain of 3pdejxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3PDejXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id t13si123908lfr.13.2020.11.04.15.20.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pdejxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z7so16932wme.8
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:29 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c101:: with SMTP id
 w1mr80924wmi.170.1604532028927; Wed, 04 Nov 2020 15:20:28 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:49 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <b223b35fb4ae833ca0ae579de37c6b9f0aa828c3.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 34/43] arm64: kasan: Add arch layer for memory tagging helpers
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
 header.i=@google.com header.s=20161025 header.b=MDmPTXJQ;       spf=pass
 (google.com: domain of 3pdejxwokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3PDejXwoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
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
 mm/kasan/kasan.h                | 22 ++++++++++++++++++++++
 2 files changed, 30 insertions(+)

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
index b5b00bff358f..e3cd6a3d2b23 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -241,6 +241,28 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
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
+#define hw_init_tags(max_tag)			arch_init_tags(max_tag)
+#define hw_get_random_tag()			arch_get_random_tag()
+#define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
+#define hw_set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b223b35fb4ae833ca0ae579de37c6b9f0aa828c3.1604531793.git.andreyknvl%40google.com.
