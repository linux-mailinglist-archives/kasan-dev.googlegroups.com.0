Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMEHW2AQMGQEAWEMJRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 77E7A31E0E9
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Feb 2021 21:59:29 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id v2sf9777252ljk.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Feb 2021 12:59:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613595569; cv=pass;
        d=google.com; s=arc-20160816;
        b=rnjkye5aTgNSdsDupXT3POk/pOKgmMZF21jGgTGUXuJvNZmzMTMiBvGQbgz1FCqnm3
         706gPpqUpGgDMOh1iL/G85AqGJYBHWtxHPrer1k0dOmW3YdLJNvCMSpYNZs9e9ldLr3Q
         uCSYFn2t0N1HduVBNabuzhPHo7ofz83IJz2Cq9VflxtENdaJq/MrgnN31V/WKjz6WWOI
         Nkb9KvGhf9vuXJgyWFGgvlUFF069x2xtGo7jypyX84jKXbQs6d8HDLTXV+hCVmHFQ8h1
         Br34anee43FystMJBLFHpEcDzPXnxmH7VkAbdiY1OKYd/3/7MgInW71PVa2EvGv2sO28
         81Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=f1bvNVKqV/BQsHfQM34mDdWZkCcae0exoOPrb4FsDT0=;
        b=CrBgpmZJJfYUitw2RZVF86l6P9FrGAKpdZT3ENc8OBfFyfyokIF1QZ793LbDxYHqQD
         02v4pi7NOI7pQ9j9QHuN2jnPGW925XUpB0L15Bxz4Kmg3ZUhA80gvP7zy38S0HwrOcoQ
         d7M3fH0YgwJoGfbHaeOigIizrdiuUTlYH2DBoifBAr2rFaGPU014Rqc8NDJ78Yd6dtDX
         hIyjKSSMlFd64j9uaEdBtodZAEU1OHwQSTkA4ku0kysG7GG0uei4SlAonU1HOBvfsmqd
         SbCbn2DzZBI5tLIaIfGPXFBxaHhmvPiF4+BPRY4toA346X5RH5/0VWR2U0LaXPlVFHGU
         8K7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="fmf1oN/3";
       spf=pass (google.com: domain of 3r4mtyaokcxqsfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3r4MtYAoKCXQSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f1bvNVKqV/BQsHfQM34mDdWZkCcae0exoOPrb4FsDT0=;
        b=Jc3ynej8W5vO1iRi5F9SMJmKBDFohIe1c/g7jXz2y/AJnesdPLZPVINgyoVI4DZSay
         QbY7eokrPh/h1wYh+SqGxZgqxXkLlG1qJq/n/qZVs+jtV34pH7FErkznkb0dceMXrTzn
         2uw2MLSJbtXFOmNcajj8gI+pvCG3ylREMgoPQ/F3Gl1gB/sCwmb4QRqIhjwot3MyLQHS
         SL6h9uaqqP/ml1v1aTW7D4xZut3lAdglrr0M1v66zkKwNflFQywJz1wFAdFzagNhqwCP
         FFz6BAJjoow4vx8j1Ontt+8bTUkSUcPUTbJhQeiNe5bZVpt3WenjCihMdWCAZa4YhhQb
         fhAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f1bvNVKqV/BQsHfQM34mDdWZkCcae0exoOPrb4FsDT0=;
        b=h9x0fNLXKDYd9U9xYJ9Ym1t3cesUNUCDp8tHI8lrof5sSrkuD28jgJiImgZ8Vd+Kto
         Vu/d9MeVQy+qtjajoUDzSy7W+w71etFNgt9REEmUc2fZ5r+sOS/wyHvBhltW26DJSQRP
         RZqeKVZ1twD9kGY2D9bKK6vAILz4Z00blrTjij0GhW1u2jGinTN9WqQF5S2M9yS5oZZx
         totkdyLcAh0aCPEVMayWV7LHQWwXMISS4+k1mb0fSbBKQpUyXtkcTLawhJNO2sBd0WzU
         eRwyq9ud78wH0IsE8IDUVrOnKMRRvowzpXx89pcYs3VHOmQWlQyc3iQ8gCdDFiHFTXjv
         E4Ag==
X-Gm-Message-State: AOAM532YHazXk6msgbSZwW651LTw2J1a6YJqXmVktAh/eV+SKcD8pwNO
	VEpauB4FvfWfOuJ5e4Vk1fk=
X-Google-Smtp-Source: ABdhPJyXxRkwqfHkOJUiRpZJ0xL8vRDXoOzsXDU++vpUHhmfmIFzs2r2G/XoPmcZcH1G2jgnt//zsw==
X-Received: by 2002:ac2:4e71:: with SMTP id y17mr421576lfs.153.1613595569072;
        Wed, 17 Feb 2021 12:59:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls2428946lfu.3.gmail; Wed,
 17 Feb 2021 12:59:28 -0800 (PST)
X-Received: by 2002:a05:6512:a95:: with SMTP id m21mr441483lfu.460.1613595568131;
        Wed, 17 Feb 2021 12:59:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613595568; cv=none;
        d=google.com; s=arc-20160816;
        b=0CAM/5MFSEwbKyF2YzsErnMFMdMTMHofGob7DwDWPvJm8CSS9AHmLeEf9IjqBcVwNg
         IgNPgWakNbbDRs1RHITL053tMNwgkc8NdF4eVHfBgrPgtb0jufgyPK5LvIApEiyUYvYu
         l+zBWZ6bVzXgtNQw9TW0h5yM8tbXwNL8lHiQOvyoLthmr3u4RwSsbiI+souEc0XM3dOS
         V/NTsuF+ThEn1wChip1rv6XO422vLgZwsMaYIRp3NAEXl6zzzw5WgKANd0p0PH2oCzfx
         ZuLwYLhijNbNrZDvlaxEXdfV2ehgRjsT2/kYmd55/VPnB+ScTR8NOlLtZOKM6siOVu3V
         nlng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=0sXbG1oj09m3SMP+1ea5iNN1KKj0U8Jo6VhHwWu92g0=;
        b=Owv73r1hyW3fP+S7MBHsy8XHEN04pPUSqgNwtpvaflHJIEPjyPHxkWitd5B/hqOz9x
         27kK8p+7UvOZxIyvEZW3aPPvtbgqGvYbz4WKbMpyYTFJyKur3lDjaZaoZ2q1xZc8Wb7/
         NplmSBqLpXeQdMt4ncbiyBcyX8CyoK6cBmSiuIojM7QrSXW/rVD9AzheKSsJO2DKtowa
         PGHH6QxG+TPfVaSK3/Wkg99HmTEjfBwK67P1+hk0BeZ63/mSBxbPcX3AqOUTkwKuI3YR
         j4zJi0yvhpRwb3+c4lRELTJcaVHCH2ElAenpWLpo7d9zoqgny9WszGQNiOmX6APjynn9
         or5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="fmf1oN/3";
       spf=pass (google.com: domain of 3r4mtyaokcxqsfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3r4MtYAoKCXQSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id z26si87108ljk.6.2021.02.17.12.59.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Feb 2021 12:59:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3r4mtyaokcxqsfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id e12so17687135wrw.14
        for <kasan-dev@googlegroups.com>; Wed, 17 Feb 2021 12:59:28 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:fc35:c4d:59c2:bb21])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:1362:: with SMTP id
 q2mr974946wrz.31.1613595567432; Wed, 17 Feb 2021 12:59:27 -0800 (PST)
Date: Wed, 17 Feb 2021 21:59:24 +0100
Message-Id: <8d79640cdab4608c454310881b6c771e856dbd2e.1613595522.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH RESEND] mm, kasan: don't poison boot memory
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="fmf1oN/3";       spf=pass
 (google.com: domain of 3r4mtyaokcxqsfvjwqcfndyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3r4MtYAoKCXQSfVjWqcfndYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--andreyknvl.bounces.google.com;
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

During boot, all non-reserved memblock memory is exposed to the buddy
allocator. Poisoning all that memory with KASAN lengthens boot time,
especially on systems with large amount of RAM. This patch makes
page_alloc to not call kasan_free_pages() on all new memory.

__free_pages_core() is used when exposing fresh memory during system
boot and when onlining memory during hotplug. This patch adds a new
FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok() through
free_pages_prepare() from __free_pages_core().

This has little impact on KASAN memory tracking.

Assuming that there are no references to newly exposed pages before they
are ever allocated, there won't be any intended (but buggy) accesses to
that memory that KASAN would normally detect.

However, with this patch, KASAN stops detecting wild and large
out-of-bounds accesses that happen to land on a fresh memory page that
was never allocated. This is taken as an acceptable trade-off.

All memory allocated normally when the boot is over keeps getting
poisoned as usual.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---

Resending with Change-Id dropped.

---
 mm/page_alloc.c | 43 ++++++++++++++++++++++++++++++++-----------
 1 file changed, 32 insertions(+), 11 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 0b55c9c95364..f10966e3b4a5 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -108,6 +108,17 @@ typedef int __bitwise fpi_t;
  */
 #define FPI_TO_TAIL		((__force fpi_t)BIT(1))
 
+/*
+ * Don't poison memory with KASAN.
+ * During boot, all non-reserved memblock memory is exposed to the buddy
+ * allocator. Poisoning all that memory lengthens boot time, especially on
+ * systems with large amount of RAM. This flag is used to skip that poisoning.
+ * Assuming that there are no references to those newly exposed pages before
+ * they are ever allocated, this has little effect on KASAN memory tracking.
+ * All memory allocated normally after boot gets poisoned as usual.
+ */
+#define FPI_SKIP_KASAN_POISON	((__force fpi_t)BIT(2))
+
 /* prevent >1 _updater_ of zone percpu pageset ->high and ->batch fields */
 static DEFINE_MUTEX(pcp_batch_high_lock);
 #define MIN_PERCPU_PAGELIST_FRACTION	(8)
@@ -384,10 +395,14 @@ static DEFINE_STATIC_KEY_TRUE(deferred_pages);
  * on-demand allocation and then freed again before the deferred pages
  * initialization is done, but this is not likely to happen.
  */
-static inline void kasan_free_nondeferred_pages(struct page *page, int order)
+static inline void kasan_free_nondeferred_pages(struct page *page, int order,
+							fpi_t fpi_flags)
 {
-	if (!static_branch_unlikely(&deferred_pages))
-		kasan_free_pages(page, order);
+	if (static_branch_unlikely(&deferred_pages))
+		return;
+	if (fpi_flags & FPI_SKIP_KASAN_POISON)
+		return;
+	kasan_free_pages(page, order);
 }
 
 /* Returns true if the struct page for the pfn is uninitialised */
@@ -438,7 +453,13 @@ defer_init(int nid, unsigned long pfn, unsigned long end_pfn)
 	return false;
 }
 #else
-#define kasan_free_nondeferred_pages(p, o)	kasan_free_pages(p, o)
+static inline void kasan_free_nondeferred_pages(struct page *page, int order,
+							fpi_t fpi_flags)
+{
+	if (fpi_flags & FPI_SKIP_KASAN_POISON)
+		return;
+	kasan_free_pages(page, order);
+}
 
 static inline bool early_page_uninitialised(unsigned long pfn)
 {
@@ -1216,7 +1237,7 @@ static void kernel_init_free_pages(struct page *page, int numpages)
 }
 
 static __always_inline bool free_pages_prepare(struct page *page,
-					unsigned int order, bool check_free)
+			unsigned int order, bool check_free, fpi_t fpi_flags)
 {
 	int bad = 0;
 
@@ -1290,7 +1311,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	debug_pagealloc_unmap_pages(page, 1 << order);
 
-	kasan_free_nondeferred_pages(page, order);
+	kasan_free_nondeferred_pages(page, order, fpi_flags);
 
 	return true;
 }
@@ -1303,7 +1324,7 @@ static __always_inline bool free_pages_prepare(struct page *page,
  */
 static bool free_pcp_prepare(struct page *page)
 {
-	return free_pages_prepare(page, 0, true);
+	return free_pages_prepare(page, 0, true, FPI_NONE);
 }
 
 static bool bulkfree_pcp_prepare(struct page *page)
@@ -1323,9 +1344,9 @@ static bool bulkfree_pcp_prepare(struct page *page)
 static bool free_pcp_prepare(struct page *page)
 {
 	if (debug_pagealloc_enabled_static())
-		return free_pages_prepare(page, 0, true);
+		return free_pages_prepare(page, 0, true, FPI_NONE);
 	else
-		return free_pages_prepare(page, 0, false);
+		return free_pages_prepare(page, 0, false, FPI_NONE);
 }
 
 static bool bulkfree_pcp_prepare(struct page *page)
@@ -1533,7 +1554,7 @@ static void __free_pages_ok(struct page *page, unsigned int order,
 	int migratetype;
 	unsigned long pfn = page_to_pfn(page);
 
-	if (!free_pages_prepare(page, order, true))
+	if (!free_pages_prepare(page, order, true, fpi_flags))
 		return;
 
 	migratetype = get_pfnblock_migratetype(page, pfn);
@@ -1570,7 +1591,7 @@ void __free_pages_core(struct page *page, unsigned int order)
 	 * Bypass PCP and place fresh pages right to the tail, primarily
 	 * relevant for memory onlining.
 	 */
-	__free_pages_ok(page, order, FPI_TO_TAIL);
+	__free_pages_ok(page, order, FPI_TO_TAIL | FPI_SKIP_KASAN_POISON);
 }
 
 #ifdef CONFIG_NEED_MULTIPLE_NODES
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d79640cdab4608c454310881b6c771e856dbd2e.1613595522.git.andreyknvl%40google.com.
