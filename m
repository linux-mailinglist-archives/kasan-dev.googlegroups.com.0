Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFUGW2AQMGQET4FUTOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 49A9031E0E3
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Feb 2021 21:56:55 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id o16sf17739429wrn.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Feb 2021 12:56:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613595415; cv=pass;
        d=google.com; s=arc-20160816;
        b=yZLVpOMEFSsBqr+t6yJIJb/ILpwSIQmo2NBKqMjfQDNxvLzCDLOJ6fZoSyhMy9FIRp
         G93PjHd9qqiDSY2POunoztYhoHJ/iXuNKCYguJoTfzjPMo274AABW3MCzqxtS+L+YS0l
         bGLVg5VGF9ojGKoEz3zxSBafzOQtLayKmyzGqxXkfLWIltgdRucOsmISge03B4i9VfSi
         OvBW4fX73OVnaTcHI21FxPxyGWKIif8Qwe3Aecst3cUIamDcxHp8W/mB1+ix6tAOIx8r
         NgAn2q6kKlIRU49N8j6y4dTOM9ve5OIIt5yD1l8aJbMh7FTjlvED5ECqO5E2BBNDZ6U+
         yxig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=+UbpWlzpozH2O9/n3g8r/Vp06LdK5uNJRFa0EpueJJg=;
        b=nIgJJCrk1GYQr7K3YgOnIIOmyptxTTyb7TRHePIdDzWI2NzzumMIli1qKFHsHxuWgO
         XGXUrMTj52hWrHVLjNCT37nGSz3w8y+STGGnXlghEkIIUrovjmrjJyoYU/3mDd9P1BUI
         n+AhWLAL3Zu+WtMT9U4gyEckTD4qIUDPjyUrL7/1Cc4LIA94Mz282CMeBpCpNlENmeyt
         R3E4ukIAuNB84yeGN8ZX3qnFLKFArWktaqeuTuYJJc2XOQRPxK13ae2lLJQegysRK7jg
         TG3PbCAGIiQ0U7ggI+iEIbqWooc98F17E1d4AyPC08YnZh9mg/qztNj56oG2RD1OHfbW
         r8KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uq+kvVIz;
       spf=pass (google.com: domain of 3fymtyaokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FYMtYAoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+UbpWlzpozH2O9/n3g8r/Vp06LdK5uNJRFa0EpueJJg=;
        b=huTFDz/P77PXT5K2141AqbQ3S01fDnog8FCf6QG74QgJhz4mcawIstqcaYZw7WrSGD
         dr24Gswe++Jht2/kSWyEonNcGr9f6OjLv+6kCBVNQxksp8NwoRVCfvyETUsZyyf9N/7H
         rhp217RgYjGiFWLBGcvMTXO1qQTjApL4Um3pdY7SQScU91SuMWAD5yAQAxZfh8VHDPC+
         oHp+AHaHqecvj9U/k3HI7iW+ALNV2ig01uYNw5O2qdZiDK2LODCcMQc0k15Rn7s3QhIa
         9Xyb4nim3uXCNRiwg3n2V5BtSf/5iZ+kXU9pcnsbIcqxU2ghWDdtFekFseUI9mMxCzus
         mkjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+UbpWlzpozH2O9/n3g8r/Vp06LdK5uNJRFa0EpueJJg=;
        b=Yi5I2T/nMnLzt9xTP7HQEPdXE2N62QH2p51EeWvN6zLdOnQzok4HkZP2dX04FCMorC
         xIhU2K149rsz3VzenBlnZa29xppMZuiIiFKCt27P+37yjBQm8/UbageEFUh7ZCKCwAWX
         YnD6i/m2bm8N/6jEhlJG3zy+MMIjAxQOc6wfDPNtmfPyh8xgvI92mqKcwHB9BlOEtoUS
         +eTmFtt822agCtvzzdoH6t2e1BO7duZBGzWEVFp8iXKSsb050O7GC7TeUPjNQyVgX9g2
         2SCH9t+KITV1uTgKp3ZwVvEJzpmERYQduQyfSUo9cbTQL/YSsV4EBVDe4JJVdO9L/DnQ
         DPGg==
X-Gm-Message-State: AOAM531dpa49sfRw7TS4JAO78yJsruHSqnaqvBhdz+g+9Ce0zqiIPvTD
	2IKcZm0ejZDiBv10YBOzUoI=
X-Google-Smtp-Source: ABdhPJyEekvmwK7Moc+ZQ7SdwtKqfVECeR3Oyf/NJgKmSU8Mk47QESIBpzHEFM+xzdABQ8Olin51hQ==
X-Received: by 2002:adf:f549:: with SMTP id j9mr927849wrp.347.1613595415046;
        Wed, 17 Feb 2021 12:56:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:60c2:: with SMTP id u185ls1282542wmb.2.gmail; Wed, 17
 Feb 2021 12:56:54 -0800 (PST)
X-Received: by 2002:a7b:c055:: with SMTP id u21mr632729wmc.68.1613595414295;
        Wed, 17 Feb 2021 12:56:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613595414; cv=none;
        d=google.com; s=arc-20160816;
        b=W8wpnR46o4FfCxCSHCf96i4oCFCvK9LxLt3UbU7C9Dvk7K5EkoYq01DsyE1aF8qdXx
         o73GylYonN+CsZhKjGFsJUX4a9U73Qj5SDUT+TA+L5qCGFJVUBKnu+1rWvD9gV07QgAb
         Z6zY9f4Ag7lx0VQIHxpIYBIShZwNCvoS43/UsGbd9yBq42kwDA4EMKJuDlOSGyOhKOay
         OBtkv4jTZQ1XWLPdQUg9dViNjB51AWKub9yj3hwQO1C4xwsnCyMyb+OhnNgwUjbiComF
         A77ciiuhmvy6yhnO5CPZu9Se+1HRf6iUMhrWaOntD/TwOziLktm7ZYc8JeoiTMdNxpHp
         pPKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=SFShG9HSiA/a5wZPjw/2OI6suzBuDo/vPg1sGXiNPU4=;
        b=to26g6vcFPopgz7iTERfxVrp/v428LpmvXbR8SIf0NeqaVaVPGhTGurW4l3cXd5Ro2
         /TlsGqkza4mEkgymtiG7TWJc7ngyJUII+3k/MffAX1hfQ+bUn1+ut2wxu+jPjMMHo42r
         owBdeUxV9oiT2Y47udSFrv6hPqYg3VygYIvOVEHfHsRy0c12W0LcJuQAPhLnph9rWI7U
         4Enfa62f2cCx/TVXLTCopoCbYruykhyhOKXUetbg93oSJFiACwIzQ4TLmCDPScqxdT4I
         u9cK0Pj+oN+wYud3047JtcKWfMSwJSDx07n4/Is9/A943TEQiSdlIwmhdpBSaunvky8/
         r/cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uq+kvVIz;
       spf=pass (google.com: domain of 3fymtyaokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FYMtYAoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id t25si125583wmj.0.2021.02.17.12.56.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Feb 2021 12:56:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fymtyaokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id v1so11490322wru.2
        for <kasan-dev@googlegroups.com>; Wed, 17 Feb 2021 12:56:54 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:fc35:c4d:59c2:bb21])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:4314:: with SMTP id
 p20mr604956wme.52.1613595413677; Wed, 17 Feb 2021 12:56:53 -0800 (PST)
Date: Wed, 17 Feb 2021 21:56:32 +0100
Message-Id: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH] mm, kasan: don't poison boot memory
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
 header.i=@google.com header.s=20161025 header.b=uq+kvVIz;       spf=pass
 (google.com: domain of 3fymtyaokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FYMtYAoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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
Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl%40google.com.
