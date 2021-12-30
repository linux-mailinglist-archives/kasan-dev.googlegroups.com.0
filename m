Return-Path: <kasan-dev+bncBAABBYUKXCHAMGQED3CFDHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A0F2481FAF
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:47 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id b8-20020a056402350800b003f8f42a883dsf10396100edd.16
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891747; cv=pass;
        d=google.com; s=arc-20160816;
        b=KgfcGiGWkv9xwcnDn3oBXfVpbBn5Q8h+vmjgy/aXXlz6dIaM4RdwQ4jC6PnkwZXVLa
         sV6aId7yNkimxi2NcR716okdsF2KsOSkUOgL4mu1wVcvuY87C4Ls5FPI0BpHmDLvbNTa
         lItozXFI3j26Cnjhnga1vSrWlWr/vD3FHeY0thzUCoWImQ3ZTjvBttJXXU25MexImruc
         3lvBxImBCgyG8B3b1vjI+fJn8plAnFber+v7QshI3GQISpbzkKc/TbBpb5L+c4o7P1eS
         zVfAUWtqFjLLhvWOihTBGzuoEKe5HQKHZa8Vl+STayh84WPRXmGfH70/4aHdklxCY/kZ
         qFFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SAYCryVCxB8bGtd6V7SGUCT9g8IzKDBjSJGRiLL35YY=;
        b=G4saRhNIfekcwD1Lg97WENKPUxQigcTdgVPjjTyouq+1vSbwef9KJpfHw4Rnlc2Pje
         +Evw33mdzPFeVHi9y5UqVf5U7i31biY3VjhsXwKHWiDOwXtZDwohIjQl4VJHuybDgOpN
         mpzc5V2/Uh7E2fROM5O0SeUBRRiFGyO3zdvNWIOCffizMyoXR+cKx152rqodcjJpAy/K
         acQgHGKGjkslh6aP2oumIOZbq+4uweFUjyo/2EvvGKpHx6fsCgFM4ojo1WksxFtB51dS
         N2Rm97bB2t4LcEkB22LULKEIz2wQF5pIHc2BocXTVnRA32/xarKnEDVHHLCTnpcXLNgU
         Gjgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AQgDkQD0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SAYCryVCxB8bGtd6V7SGUCT9g8IzKDBjSJGRiLL35YY=;
        b=YTaYk3xiuWc0ZuqDy9553ogQQK8C2/1BZXb3/Xypo0RUMbTTJM/zxwpRth3KHe3Cux
         1Sl4a68EQHDSJwiw0gFjGm3Q84XTJCF0aVGDwIHyrvZmpXJ+IaCI0PqBeLNBPCfBQ3F7
         BcCR/RRBpCclTNZ4WBN4HINo5k4MI2pk51fPzsM6VSYwlDjoEeueasEXAszm2714DaHn
         9Hm3Zu5rxXKngZmYrPkN3yKFMRkuj+lU4i6qR1SSV7sDcFWd3wY7GE9AClqt5+x/QPal
         K6Aoivkk1IcX62D/hm3Zj5+b+LF/A3i0VoNxoC22RC+KE2qXqmIGFYrFlk3nLFs1/Emv
         Nefw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SAYCryVCxB8bGtd6V7SGUCT9g8IzKDBjSJGRiLL35YY=;
        b=6sHGX5yaopBUAXONyPKz2LUC56ITr53Qi79EYfG1kW6d23NsPKSrJl5w/UC/mMEr+i
         CEzLKqEsuHi3QqpRr5gZnD0TSQsFrKgzvCnt+ExF6BzAPgTnPWPT8Kh2lkLCof0n/vEI
         svjgUgrM3/i/t4d+SNUIY7IwyaLD9ZgXskbt7ET5V6taTDT3+0bOQtFAEPQ3ylCN4iqR
         DMyYZXAOSuIpfiy7IJaWiXNGAlevU86q7jRZOy5AdPx++QuHTSYnZPB7Ej9BdQlKoFHH
         7VN7U02UDoMNyq0DaIvTane4UL1pkIsVlo95gcuLXguSDy2B619coRr9ZaTHT2dXnwVy
         eBdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531SJ+MhmZVPnDKcKO7cOxYf73wwToTcTCf8yyuVlpaJ+D9ltvs7
	r1UuHZ5twHG3nVdo/M9vn1k=
X-Google-Smtp-Source: ABdhPJyLE9/zZttSZN9lzpFXLtI33rI0DRxYgsX2ukH96E+NmPFT0jM8h/Y0DX2ThhW07xcP+nmVOQ==
X-Received: by 2002:a17:907:9602:: with SMTP id gb2mr25358886ejc.510.1640891746986;
        Thu, 30 Dec 2021 11:15:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:9617:: with SMTP id gb23ls8520087ejc.6.gmail; Thu,
 30 Dec 2021 11:15:46 -0800 (PST)
X-Received: by 2002:a17:907:3e9b:: with SMTP id hs27mr26240196ejc.590.1640891746250;
        Thu, 30 Dec 2021 11:15:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891746; cv=none;
        d=google.com; s=arc-20160816;
        b=mKYWSEEOw9wXKXfPMzUcNSpzbo8hXE2z6ha5/G43b9NvehSxm5fpnz7h1LRW8iGuHM
         TOZqw56stJvF4f1HAPDjYXGWFG3SVqh3Xq8VxPQkURKx9G1pOlTTMag2LEilMcc7+N+W
         +LB/bzsEhlvq7BrF1rOQ4R/AfK1r7dn3Mc8ApQlo/VLRx/ZV2aQ4GrzO3MRr+ka0LeVK
         g8TL3QBBHQ51DaBKK7qXUK/d31NKoZ5MIkyT8qPWSYpAsduSVD28Kupn6NVbQVz59Yr4
         lyq9Nyc/qCPThrxJLdDSIrHyBab8OA6f2LCaDQNht1xaEHd4q3f4Awdqmninzg0fCYqZ
         Uwbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vAwQcHTlCiYChpYnlNq+QkugFDzxho9e0I/gAsV+YMU=;
        b=GIHfl1cCjWoW3JB4zzQDbdhl/HYQQ9xgfj1PBzbenlbczHBnGk3W70c9WIp0zPU2u6
         AvNdW4YK4jQ22+M9CGjOd5D1WmwaYkd59RAbIUDi0tSaSRUkrBT9sRkviidH6yjs3Cl9
         ru2VGk3M4okoWcR2ZR//wNfXky6yHzFRG+MX/4dBrUSKV2ej9opn2RsBAqRd9KgY1LuJ
         4+gKHenZkJ8fDjKaudVM2CH8OTEzORXgbm69wmvaSc8oM5kN2oESHyVofGzSH69MIjDc
         JM8SuNDCsE2bOvaB5o1k1IpOs2YfeSAcMYWfBpAFKLCYItNUEOIG6eojT2EM7oNG5xF/
         ZrNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AQgDkQD0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id bo19si941552edb.2.2021.12.30.11.15.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH mm v5 28/39] kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
Date: Thu, 30 Dec 2021 20:14:53 +0100
Message-Id: <d23aabe9b20593cbae6c0e304e267f0f8cfe0bfb.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AQgDkQD0;       spf=pass
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

Add a new GFP flag __GFP_SKIP_KASAN_UNPOISON that allows skipping KASAN
poisoning for page_alloc allocations. The flag is only effective with
HW_TAGS KASAN.

This flag will be used by vmalloc code for page_alloc allocations
backing vmalloc() mappings in a following patch. The reason to skip
KASAN poisoning for these pages in page_alloc is because vmalloc code
will be poisoning them instead.

Also reword the comment for __GFP_SKIP_KASAN_POISON.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v4->v5:
- Cosmetic changes to __def_gfpflag_names_kasan and __GFP_BITS_SHIFT.

Changes v3->v4:
- Only define __GFP_SKIP_KASAN_POISON when CONFIG_KASAN_HW_TAGS is
  enabled.

Changes v2->v3:
- Update patch description.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h            | 21 +++++++++++++--------
 include/trace/events/mmflags.h |  5 +++--
 mm/page_alloc.c                | 31 ++++++++++++++++++++++---------
 3 files changed, 38 insertions(+), 19 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 9dce456d147a..487126f089e1 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -55,12 +55,14 @@ struct vm_area_struct;
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
 #ifdef CONFIG_KASAN_HW_TAGS
-#define ___GFP_SKIP_KASAN_POISON	0x1000000u
+#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
+#define ___GFP_SKIP_KASAN_POISON	0x2000000u
 #else
+#define ___GFP_SKIP_KASAN_UNPOISON	0
 #define ___GFP_SKIP_KASAN_POISON	0
 #endif
 #ifdef CONFIG_LOCKDEP
-#define ___GFP_NOLOCKDEP	0x2000000u
+#define ___GFP_NOLOCKDEP	0x4000000u
 #else
 #define ___GFP_NOLOCKDEP	0
 #endif
@@ -237,22 +239,25 @@ struct vm_area_struct;
  * intended for optimization: setting memory tags at the same time as zeroing
  * memory has minimal additional performace impact.
  *
- * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
- * on deallocation. Typically used for userspace pages. Currently only has an
- * effect in HW tags mode.
+ * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page allocation.
+ * Only effective in HW_TAGS mode.
+ *
+ * %__GFP_SKIP_KASAN_POISON makes KASAN skip poisoning on page deallocation.
+ * Typically, used for userspace pages. Only effective in HW_TAGS mode.
  */
 #define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)
 #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
 #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
 #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
-#define __GFP_SKIP_KASAN_POISON	((__force gfp_t)___GFP_SKIP_KASAN_POISON)
+#define __GFP_SKIP_KASAN_UNPOISON ((__force gfp_t)___GFP_SKIP_KASAN_UNPOISON)
+#define __GFP_SKIP_KASAN_POISON   ((__force gfp_t)___GFP_SKIP_KASAN_POISON)
 
 /* Disable lockdep for GFP context tracking */
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (24 +					\
-			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
+#define __GFP_BITS_SHIFT (24 +						\
+			  2 * IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
 			  IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index 414bf4367283..5ffc7bdce91f 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -51,8 +51,9 @@
 	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"}	\
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define __def_gfpflag_names_kasan					      \
-	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"}
+#define __def_gfpflag_names_kasan ,					       \
+	{(unsigned long)__GFP_SKIP_KASAN_POISON,   "__GFP_SKIP_KASAN_POISON"}, \
+	{(unsigned long)__GFP_SKIP_KASAN_UNPOISON, "__GFP_SKIP_KASAN_UNPOISON"}
 #else
 #define __def_gfpflag_names_kasan
 #endif
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index a07f9e9b0abc..102f0cd8815e 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2395,6 +2395,26 @@ static bool check_new_pages(struct page *page, unsigned int order)
 	return false;
 }
 
+static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
+{
+	/* Don't skip if a software KASAN mode is enabled. */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		return false;
+
+	/* Skip, if hardware tag-based KASAN is not enabled. */
+	if (!kasan_hw_tags_enabled())
+		return true;
+
+	/*
+	 * With hardware tag-based KASAN enabled, skip if either:
+	 *
+	 * 1. Memory tags have already been cleared via tag_clear_highpage().
+	 * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
+	 */
+	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
+}
+
 inline void post_alloc_hook(struct page *page, unsigned int order,
 				gfp_t gfp_flags)
 {
@@ -2434,15 +2454,8 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by the loop above. */
 		init = false;
 	}
-	/*
-	 * If either a software KASAN mode is enabled, or,
-	 * in the case of hardware tag-based KASAN,
-	 * if memory tags have not been cleared via tag_clear_highpage().
-	 */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
-	    IS_ENABLED(CONFIG_KASAN_SW_TAGS) ||
-	    kasan_hw_tags_enabled() && !init_tags) {
-		/* Mark shadow memory or set memory tags. */
+	if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
+		/* Unpoison shadow memory or set memory tags. */
 		kasan_unpoison_pages(page, order, init);
 
 		/* Note that memory is already initialized by KASAN. */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d23aabe9b20593cbae6c0e304e267f0f8cfe0bfb.1640891329.git.andreyknvl%40google.com.
